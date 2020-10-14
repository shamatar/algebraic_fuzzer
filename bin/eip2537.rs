extern crate algebraic_fuzzer;
use algebraic_fuzzer::eip_2537_fuzzer::*;

fn main() {
    let driver = lain::driver::FuzzerDriver::<()>::new(4);
    let driver = std::sync::Arc::from(driver);

    let ctrlc_driver = driver.clone();

    ctrlc::set_handler(move || {
        ctrlc_driver.signal_exit();
    }).expect("couldn't set CTRL-C handler");

    lain::driver::start_fuzzer(driver.clone(),
        move |mutator, _ctx: &mut (), _| {
            let mut generation_context = GenerationContext::create();
            let mut targets = create_runners(false);
            let idx = mutator.gen_range(0, targets.len());
            let runner = &mut targets[idx];

            let input = runner.generate(mutator, &mut generation_context);
            let output = runner.run(&input);

            Ok(())
        }
    );

    driver.join_threads();

    println!("Finished in {} iterations", driver.num_iterations());
}