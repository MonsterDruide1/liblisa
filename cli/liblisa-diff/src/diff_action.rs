use std::{collections::HashMap, error::Error, fs::{self, File}, io::BufReader, mem, path::PathBuf, sync::{Mutex, atomic::{AtomicBool, Ordering}, mpsc::{RecvTimeoutError, channel}}, thread::{scope, spawn}, time::{Duration, Instant}};

use liblisa::{arch::x64::X64Arch, oracle::Oracle};
use liblisa::encoding::Encoding;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa_libcli::{clear_screen, threadpool::ThreadPool};

use crate::{diff::create_state, diff_postprocess::postprocess, diff_types::DiffItem};
use crate::diff_types::{Diff, DiffError, DiffRuntimeData};
use crate::state_diff;
use crate::dummy_oracle_source;

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
    Export {
        result: ResultType,
        target: PathBuf,
    },
    PostprocessMismatches,
    DiscardResults {
        result: ResultType,
    },
    TestDiff {
        todo_index: usize,
        diff_index: usize,
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
                let diff: Mutex<(Diff, DiffRuntimeData)> = Mutex::new({
                    let diff: Diff = serde_json::from_reader(file).unwrap();
                    let todo = (0..diff.items.len()).filter(|&i| diff.items[i].result.is_none()).collect();
                    let runtime_data = DiffRuntimeData {
                        last_check: Instant::now(),
                        pending: Vec::new(),
                        todo,
                    };
                    (diff, runtime_data)
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

                            if last_save.elapsed() >= Duration::from_secs(10) {
                                self.save_state(&diff.lock().unwrap().0);
                                last_save = Instant::now();
                            }
                        }
                    });

                    {
                        let mut pool = ThreadPool::from_work(
                            scope, dummy_oracle_source::create_dummy_oracle_source::<X64Arch>, &(), &diff, &save_artifact
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
                self.save_state(&diff.lock().unwrap().0);

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

                for (i, item) in diff.items.iter().enumerate() {
                    let Some(result) = &item.result else {
                        continue;
                    };
                    match &result.diffs {
                        Ok(diffs) if diffs.is_empty() && *r == ResultType::OK => {
                            println!("Index {i}: {}", item.description);
                            println!("  Result: OK");
                        },
                        Ok(diffs) if !diffs.is_empty() && *r == ResultType::Mismatch => {
                            println!("Index {i}: {}", item.description);
                            println!("  Result: MISMATCH");
                            for (j, diff) in diffs.iter().enumerate() {
                                println!("    Diff[{}-{}]: {:?}", i, j, diff);
                            }
                        },
                        Err(e) if *r == ResultType::Failure => {
                            println!("Index {i}: {}", item.description);
                            println!("  Result: FAILURE");
                            println!("    Error: {}", e);
                        },
                        _ => {},
                    }
                }
            }
            Verb::PostprocessMismatches => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let diff: Diff = serde_json::from_reader(file).unwrap();
                unsafe {
                    let (explained, unexplained) = postprocess(&diff);
                    let mut counts = HashMap::new();
                    for explain in &explained {
                        *counts.entry(explain.name()).or_insert(0) += 1;
                    }
                    println!("Explained mismatches: {}", explained.len());
                    for (explain_type, count) in counts {
                        println!("  {:?}: {}", explain_type, count);
                    }
                    println!("Unexplained mismatches: {}", unexplained.len());
                    for item in unexplained {
                        let instr = item.instr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                        println!("  [{}-{}]: {} = {} => {:?}", item.item_index, item.diff_index, instr, item.iclass, item.diff_type);
                    }
                }
            }
            Verb::DiscardResults { result } => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let mut diff: Diff = serde_json::from_reader(file).unwrap();

                for DiffItem { description, result: r, .. } in diff.items.iter_mut() {
                    let Some(res) = r else {
                        continue;
                    };
                    let retain = match &res.diffs {
                        Ok(diffs) if diffs.is_empty() && *result == ResultType::OK => false,
                        Ok(diffs) if !diffs.is_empty() && *result == ResultType::Mismatch => false,
                        Err(e) if *result == ResultType::Failure => false,
                        _ => true,
                    };
                    if !retain {
                        println!("Discarding result for {}", description);
                        *r = None;
                    }
                }

                let file = File::create(self.state_path()).unwrap();
                serde_json::to_writer(file, &diff).unwrap();
            }
            Verb::Export { result, target } => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let mut diff: Diff = serde_json::from_reader(file).unwrap();

                println!("Filtering...");
                diff.items.retain(|item| {
                    let Some(res) = r else {
                        return false;
                    };
                    match &res.diffs {
                        Ok(diffs) if diffs.is_empty() && *result == ResultType::OK => true,
                        Ok(diffs) if !diffs.is_empty() && *result == ResultType::Mismatch => true,
                        Err(e) if *result == ResultType::Failure => true,
                        _ => false,
                    }
                });
                for item in &mut diff.items {
                    item.instructions = vec![];
                }

                println!("Exporting {} items...", diff.items.len());
                let file = File::create(target).unwrap();
                serde_json::to_writer(file, &diff).unwrap();
            }
            Verb::TestDiff { todo_index, diff_index } => {
                println!("Loading base data...");
                let file = File::open(self.state_path()).unwrap();
                let diff: Diff = serde_json::from_reader(file).unwrap();

                let todo = &diff.items[*todo_index];

                println!("Testing todo index {todo_index}, diff index {diff_index}: {}", todo.description);
                let Some(result) = &todo.result else {
                    println!("  Result: ???");
                    println!("    Error: No result for this todo index");
                    return;
                };
                let diffs = match &result.diffs {
                    Ok(diffs) => diffs,
                    Err(e) => {
                        println!("  Result: FAILURE");
                        println!("    Error: {}", e);
                        println!("  Cannot test diff, no state to run!");
                        return;
                    }
                };
                let diff = diffs.get(*diff_index).unwrap_or_else(|| {
                    panic!("Diff index {diff_index} is out of bounds for todo index {todo_index} ({} diffs)", diffs.len());
                });
                
                let mut state = create_state();
                println!("Before: {:?}", diff.example_before);
                println!("Running instruction...");
                let r1 = state.o1.observe(&diff.example_before);
                let r2 = state.o2.observe(&diff.example_before);
                let diffs = state_diff::compare(&r1, &r2);

                println!("  Ghidra result: {:?}", r1);
                println!("  VM result: {:?}", r2);
                println!("  Recorded diff: {:?}", diff.diff_type);
                println!("  New diffs: {:?}", diffs);
            }
        }
    }

    fn print_status(diff: &Diff) {
        let mut ok = 0;
        let mut mismatch = 0;
        let mut failure_types = Vec::<(&DiffError, usize)>::new();
        for DiffItem { result, .. } in diff.items.iter() {
            match result.as_ref().map(|r| &r.diffs) {
                Some(Ok(diffs)) if diffs.is_empty() => ok += 1,
                Some(Ok(_)) => mismatch += 1,
                Some(Err(e)) => {
                    let entry = failure_types.iter_mut().find(|(err, _)| *err == e);
                    if let Some((_, count)) = entry {
                        *count += 1;
                    } else {
                        failure_types.push((&e, 1));
                    }
                }
                None => {},
            }
        }
        let failure = failure_types.iter().map(|(_, count)| *count).sum::<usize>();

        let num_processed = ok + mismatch + failure;
        let num_encodings = diff.items.len();
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
