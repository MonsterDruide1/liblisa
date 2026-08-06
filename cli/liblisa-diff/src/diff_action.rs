use std::{error::Error, fs::{self, File}, io::BufReader, path::PathBuf, sync::{Mutex, atomic::{AtomicBool, Ordering}, mpsc::{RecvTimeoutError, channel}}, thread::{scope, spawn}, time::{Duration, Instant}};

use liblisa::{Instruction, arch::x64::X64Arch};
use liblisa::encoding::Encoding;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa_libcli::{clear_screen, threadpool::ThreadPool};

use crate::{diff::{create_state, run_instr}, diff_types::NUM_STATES_PER_INSTR, dummy_oracle_source};
use crate::diff_types::{Diff, DiffError, DiffResult, DiffRuntimeData};

#[derive(Clone, Debug, PartialEq, clap::ValueEnum)]
enum ResultType {
    OK,
    Mismatch,
    Failure,
}

#[derive(Clone, Debug, clap::Parser)]
enum Verb {
    Create {
        encodings: PathBuf,
    },
    Run {
        #[clap(long)]
        threads: Option<usize>,

        #[clap(
            long,
            help = "ramps the number of threads up to this value by adding 4 threads every 15 minutes"
        )]
        ramp_up: Option<usize>,
    },
    Status {
        #[clap(long)]
        watch: bool,

        #[clap(short = 't', long)]
        time: Option<u64>,
    },
    Dump {
        result: ResultType,
    },
    Test {
        instr: Instruction,
    },
}

#[derive(Clone, Debug, clap::Parser)]
pub struct DiffCommand {
    dir: PathBuf,

    #[clap(subcommand)]
    verb: Verb,
}

impl DiffCommand {
    fn save_state(&self, state: &Diff) {
        {
            let file = File::create(self.tmp_state_path()).unwrap();
            serde_json::to_writer(file, state).unwrap();
        }

        fs::rename(self.tmp_state_path(), self.state_path()).unwrap();
    }

    fn tmp_state_path(&self) -> PathBuf {
        self.dir.join(".tmp.state.json")
    }
    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn run(&self) {
        match &self.verb {
            Verb::Create { encodings } => {
                fs::create_dir_all(&self.dir).unwrap();
                let encodings: Vec<Encoding<X64Arch, SynthesizedComputation>> =
                    serde_json::from_reader(BufReader::new(File::open(&encodings).unwrap())).unwrap();

                let synthesis = Diff::create(encodings);
                let file = File::create(self.state_path()).unwrap();
                serde_json::to_writer(file, &synthesis).unwrap();
            }
            Verb::Run { threads, ramp_up } => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let synthesis: Diff = serde_json::from_reader(file).unwrap();
                let synthesis: Mutex<(Diff, DiffRuntimeData)> = Mutex::new({
                    let runtime_data = DiffRuntimeData {
                        last_check: Instant::now(),
                        pending: Vec::new(),
                    };
                    (synthesis, runtime_data)
                });

                let save_artifact = move |_| {};

                let (send, recv) = channel();
                spawn(|| {
                    for line in std::io::stdin().lines() {
                        send.send(line).unwrap();
                    }

                    drop(send);
                });

                let running = AtomicBool::new(true);
                scope(|scope| -> Result<(), Box<dyn Error>> {
                    scope.spawn(|| {
                        let mut last_save = Instant::now();
                        while running.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_secs(5));

                            if last_save.elapsed() >= Duration::from_secs(30) {
                                self.save_state(&synthesis.lock().unwrap().0);
                                last_save = Instant::now();
                            }
                        }
                    });

                    {
                        let mut pool = ThreadPool::from_work(
                            scope, dummy_oracle_source::create_dummy_oracle_source::<X64Arch>, &(), &synthesis, &save_artifact
                        );

                        // TODO: Automatically determine the right size
                        pool.resize(threads.unwrap_or(2));

                        let mut last_ramp_up = Instant::now();
                        loop {
                            match recv.recv_timeout(Duration::from_secs(5)) {
                                Ok(line) => {
                                    let line = line?;
                                    let command = line.split(' ').map(str::trim).collect::<Vec<_>>();
                                    match &command[..] {
                                        ["stop"] => break,
                                        ["threads", num] => match num.parse::<usize>() {
                                            Ok(num) => {
                                                println!("Resizing thread pool to {num}...");
                                                pool.resize(num);
                                                println!("Thread pool resized to {num}");

                                                if ramp_up.as_ref().is_some() {
                                                    println!("Ramp-up cancelled because of manual input");
                                                }
                                            },
                                            Err(e) => println!("{e}"),
                                        },
                                        _ => println!("Commands available: stop"),
                                    }
                                },
                                Err(RecvTimeoutError::Disconnected) => break,
                                Err(RecvTimeoutError::Timeout) => (),
                            }

                            if last_ramp_up.elapsed() >= Duration::from_secs(30 * 60) {
                                if let Some(ramp_up) = ramp_up {
                                    let current = pool.current_num_threads();
                                    let new_num = (current + 4).min(*ramp_up);
                                    pool.resize(new_num);
                                }

                                last_ramp_up = Instant::now();
                            }
                        }

                        // By resizing to 0, all threads will be terminated
                        println!("Stopping all threads...");
                        pool.resize(0);
                    }

                    running.store(false, Ordering::SeqCst);

                    println!("Waiting for all scoped threads to terminate...");

                    Ok(())
                })
                .unwrap();

                println!("Performing last save...");
                self.save_state(&synthesis.lock().unwrap().0);

                println!("OK!");
            }
            Verb::Status { watch, time } => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let diff: Diff = serde_json::from_reader(file).unwrap();

                if *watch {
                    loop {
                        // TODO: Watch artifacts file and reload on write!
                        let file = File::open(self.state_path()).unwrap();
                        let diff: Diff = serde_json::from_reader(file).unwrap();
                        clear_screen();
                        Self::print_status(&diff);

                        if let Some(time) = time {
                            std::thread::sleep(Duration::from_secs(*time));
                        } else {
                            std::io::stdin().read_line(&mut String::new()).unwrap();
                        }
                    }
                } else {
                    Self::print_status(&diff);
                }
            }
            Verb::Dump { result: r } => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let diff: Diff = serde_json::from_reader(file).unwrap();

                for (index, DiffResult { diffs: result }) in diff.results.iter() {
                    match result {
                        Ok(diffs) if diffs.is_empty() && *r == ResultType::OK => {
                            println!("Index {index}: {}", diff.todos[*index].description);
                            println!("  Result: OK");
                        },
                        Ok(diffs) if !diffs.is_empty() && *r == ResultType::Mismatch => {
                            println!("Index {index}: {}", diff.todos[*index].description);
                            println!("  Result: MISMATCH");
                            for diff in diffs {
                                println!("    Diff: {:?}", diff);
                            }
                        },
                        Err(e) if *r == ResultType::Failure => {
                            println!("Index {index}: {}", diff.todos[*index].description);
                            println!("  Result: FAILURE");
                            println!("    Error: {}", e);
                        },
                        _ => {},
                    }
                }
            }
            Verb::Test { instr} => {
                let mut state = create_state();
                println!("Running instruction...");
                println!("{:?}", run_instr(instr, NUM_STATES_PER_INSTR, &mut state));
                println!("Observed diffs: {:?}", state.diffs);
            }
        }
    }

    fn print_status(diff: &Diff) {
        let mut ok = 0;
        let mut mismatch = 0;
        let mut failure_types = Vec::<(&DiffError, usize)>::new();
        for (_, DiffResult { diffs: result }) in diff.results.iter() {
            match result {
                Ok(diffs) if diffs.is_empty() => ok += 1,
                Ok(_) => mismatch += 1,
                Err(e) => {
                    let entry = failure_types.iter_mut().find(|(err, _)| *err == e);
                    if let Some((_, count)) = entry {
                        *count += 1;
                    } else {
                        failure_types.push((e, 1));
                    }
                }
            }
        }
        let failure = failure_types.iter().map(|(_, count)| *count).sum::<usize>();

        let num_processed = diff.results.len();
        let num_encodings = diff.todos.len();
        let seconds_running = diff.runtime_ms / 1000;
        let hours_running = seconds_running as f64 / 3600.0;
        let encodings_per_hour = num_processed as f64 / hours_running;
        println!(
            "Processed {num_processed} / {num_encodings} encodings in {hours_running:.1}h ({encodings_per_hour:.1} encodings/h)"
        );
        println!("    {ok} encodings are OK");
        println!("    {mismatch} encodings have mismatches");
        println!("    {failure} encodings failed completely");
        for (err, count) in failure_types {
            println!("        {count} encodings failed with error: {}", err);
        }

        let remaining = (num_encodings - num_processed) as f64 / encodings_per_hour;
        let percent = num_processed as f64 * 100.0 / num_encodings as f64;
        println!("Progress: {percent:.1}% - {remaining:.1}h remaining");
    }
}
