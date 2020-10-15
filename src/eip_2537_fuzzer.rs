use lain::prelude::*;
use lain::rand::Rng;

use derivative::*;
use num_traits::*;
use num_bigint::BigUint;

use eth_pairings::engines::bls12_381;
use eth_pairings::public_interface::{decode_fp, decode_g1, decode_g2};
use eth_pairings::traits::*;
use eth_pairings::square_root::*;
use eth_pairings::public_interface::eip2537::EIP2537Executor;
use eth_pairings_go_2537::*;
use std::fmt::Write;

pub struct GenerationContext<R: Rng> {
    pub scalar_generation_fn: Box<dyn Fn(&mut Mutator<R>, ScalarGenerationFlags) -> Vec<u8> + Send + Sync + 'static>,
    pub fp_generation_fn: Box<dyn Fn(&mut Mutator<R>, FieldGenerationFlags) -> Vec<u8> + Send + Sync + 'static>,
    pub fp2_generation_fn: Box<dyn Fn(&mut Mutator<R>, FieldGenerationFlags) -> Vec<u8> + Send + Sync + 'static>,
    pub g1_generation_fn: Box<dyn Fn(&mut Mutator<R>, EcPointGenerationFlag) -> Vec<u8> + Send + Sync + 'static>,
    pub g2_generation_fn: Box<dyn Fn(&mut Mutator<R>, EcPointGenerationFlag) -> Vec<u8> + Send + Sync + 'static>,
}

impl<R: Rng> GenerationContext<R> {
    pub fn create() -> Self {
        let scalar_generation_fn = move |mutator: &mut Mutator<R>, flags: ScalarGenerationFlags| {
            match flags {
                ScalarGenerationFlags::ValidWithPropabilityOfZero(prob) => {
                    let make_zero = mutator.gen_chance(prob);
                    let mut result = vec![0u8; SCALAR_BYTE_LENGTH];
                    if !make_zero {
                        mutator.rng_mut().fill_bytes(&mut result);
                    }

                    result
                }
                ScalarGenerationFlags::InvalidLength => {
                    let len = mutator.gen_range(0, 64);
                    let mut result = vec![0u8; len];
                    mutator.rng_mut().fill_bytes(&mut result);

                    result
                },
            }
        };

        let modulus = BigUint::from_str_radix("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10).unwrap();

        let m = modulus.clone();
        let fp_generation_fn = move |mutator: &mut Mutator<R>, flags: FieldGenerationFlags| {
            match flags {
                FieldGenerationFlags::CreateZero => {
                    vec![0u8; SERIALIZED_FP_BYTE_LENGTH]
                }
                FieldGenerationFlags::CreateValid => {
                    let (_, enc) = make_random_fp_with_encoding(mutator.rng_mut(), &m);

                    enc
                },
                FieldGenerationFlags::CreateNotInField => {
                    make_invalid_encoding_fp(mutator.rng_mut(), &m, true)
                },
                FieldGenerationFlags::CreateOtherInvalidEncoding => {
                    make_invalid_encoding_fp(mutator.rng_mut(), &m, false)
                },
                FieldGenerationFlags::CreateInvalidLength => {
                    let len = mutator.gen_range(0, SERIALIZED_FP_BYTE_LENGTH * 2);
                    let mut result = vec![0u8; len];
                    mutator.rng_mut().fill_bytes(&mut result);

                    result
                }
            }
        };

        let m = modulus.clone();
        let fp2_generation_fn = move |mutator: &mut Mutator<R>, flags: FieldGenerationFlags| {
            match flags {
                FieldGenerationFlags::CreateZero => {
                    vec![0u8; SERIALIZED_FP2_BYTE_LENGTH]
                },
                FieldGenerationFlags::CreateValid => {
                    let (_, enc) = make_random_fp2_with_encoding(mutator.rng_mut(), &m);

                    enc
                },
                FieldGenerationFlags::CreateNotInField => {
                    make_invalid_encoding_fp2(mutator.rng_mut(), &m, true)
                },
                FieldGenerationFlags::CreateOtherInvalidEncoding => {
                    make_invalid_encoding_fp2(mutator.rng_mut(), &m, false)
                },
                FieldGenerationFlags::CreateInvalidLength => {
                    let len = mutator.gen_range(0, SERIALIZED_FP2_BYTE_LENGTH * 2);
                    let mut result = vec![0u8; len];
                    mutator.rng_mut().fill_bytes(&mut result);

                    result
                }
            }
        };

        let m = modulus.clone();
        let g1_generation_fn = move |mutator: &mut Mutator<R>, flags: EcPointGenerationFlag| {
            match flags {
                EcPointGenerationFlag::CreateInfinity => {
                    vec![0u8; SERIALIZED_G1_POINT_BYTE_LENGTH]
                },
                EcPointGenerationFlag::CreateValid => {
                    let enc = make_random_g1_with_encoding(mutator.rng_mut());

                    enc
                },
                EcPointGenerationFlag::CreateNotOnCurve => {
                    let (_, random_fp) = make_random_fp_with_encoding(mutator.rng_mut(), &m);
                    let replace_x: bool = mutator.rng_mut().gen();
                    let mut encoding = make_random_g1_with_encoding(mutator.rng_mut());
                    if replace_x {
                        encoding[0..SERIALIZED_FP_BYTE_LENGTH].copy_from_slice(&random_fp);
                    } else {
                        encoding[SERIALIZED_FP_BYTE_LENGTH..].copy_from_slice(&random_fp);
                    }

                    encoding
                },
                EcPointGenerationFlag::CreateInvalidSubgroup => {
                    make_g1_in_invalid_subgroup(mutator.rng_mut())
                },
                EcPointGenerationFlag::CreateOtherInvalidEncoding => {
                    let mut input = vec![];
                    input.extend(make_invalid_encoding_fp(mutator.rng_mut(), &m, false));
                    input.extend(make_invalid_encoding_fp(mutator.rng_mut(), &m, false));

                    input
                }
                FieldGenerationFlags::CreateInvalidLength => {
                    let len = mutator.gen_range(0, SERIALIZED_G1_POINT_BYTE_LENGTH * 2);
                    let mut result = vec![0u8; len];
                    mutator.rng_mut().fill_bytes(&mut result);

                    result
                }
            }
        };

        let m = modulus.clone();
        let g2_generation_fn = move |mutator: &mut Mutator<R>, flags: EcPointGenerationFlag| {
            match flags {
                EcPointGenerationFlag::CreateInfinity => {
                    vec![0u8; SERIALIZED_G2_POINT_BYTE_LENGTH]
                },
                EcPointGenerationFlag::CreateValid => {
                    let enc = make_random_g2_with_encoding(mutator.rng_mut());

                    enc
                },
                EcPointGenerationFlag::CreateNotOnCurve => {
                    let (_, random_fp) = make_random_fp2_with_encoding(mutator.rng_mut(), &m);
                    let replace_x: bool = mutator.rng_mut().gen();
                    let mut encoding = make_random_g2_with_encoding(mutator.rng_mut());
                    if replace_x {
                        encoding[0..SERIALIZED_FP2_BYTE_LENGTH].copy_from_slice(&random_fp);
                    } else {
                        encoding[SERIALIZED_FP2_BYTE_LENGTH..].copy_from_slice(&random_fp);
                    }

                    encoding
                },
                EcPointGenerationFlag::CreateInvalidSubgroup => {
                    make_g2_in_invalid_subgroup(mutator.rng_mut())
                },
                EcPointGenerationFlag::CreateOtherInvalidEncoding => {
                    let mut input = vec![];
                    input.extend(make_invalid_encoding_fp2(mutator.rng_mut(), &m, false));
                    input.extend(make_invalid_encoding_fp2(mutator.rng_mut(), &m, false));

                    input
                },
                FieldGenerationFlags::CreateInvalidLength => {
                    let len = mutator.gen_range(0, SERIALIZED_G2_POINT_BYTE_LENGTH * 2);
                    let mut result = vec![0u8; len];
                    mutator.rng_mut().fill_bytes(&mut result);

                    result
                }
            }
        };

        Self {
            scalar_generation_fn: Box::new(scalar_generation_fn) as _,
            fp_generation_fn: Box::new(fp_generation_fn) as _,
            fp2_generation_fn: Box::new(fp2_generation_fn) as _,
            g1_generation_fn: Box::new(g1_generation_fn) as _,
            g2_generation_fn: Box::new(g2_generation_fn) as _,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct FuzzerTarget<R: Rng> {
    pub verbose_errors: bool,
    pub verbose_results: bool,
    pub op_name: &'static str,
    #[derivative(Debug="ignore")]
    pub generator: Box<dyn Fn(&[u8], &mut Mutator<R>, &mut GenerationContext<R>) -> Vec<u8> + Send + Sync + 'static>,
    #[derivative(Debug="ignore")]
    pub executor: Box<dyn Fn(&[u8]) -> Vec<Result<Vec<u8>, String>> + Send + Sync + 'static>,
}

impl<R: Rng> FuzzerTarget<R> {
    fn map_result_verbose<T: AsRef<[u8]>, U: std::fmt::Debug>(&self, res: Result<T, U>) -> Result<Vec<u8>, ()> {
        res.map_err(|err| {
            if self.verbose_errors {
                println!("Target: {}, returned error: {:?}", self.op_name, err);
            }
    
            ()
        }) 
        .map(|res| {
            if self.verbose_results {
                println!("Target: {}, successful call", self.op_name);
            }
            res.as_ref().to_vec()
        })
    }
}

impl<R: Rng> FuzzerTarget<R> {
    pub fn generate(&mut self, mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
        self.generator.as_mut()(&[], mutator, context)
    }
    pub fn run(&self, input: &[u8]) -> Result<(), String> {
        let results: Vec<_> = self.executor.as_ref()(input).into_iter()
                            .map(|el| self.map_result_verbose(el)).collect();

        compare_multiple_structured_results(&results)
    }
}
#[derive(Derivative)]
#[derivative(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ScalarGenerationFlags{
    ValidWithPropabilityOfZero(f64),
    InvalidLength
}

impl lain::traits::NewFuzzed for ScalarGenerationFlags {
    type RangeType = ();
    fn new_fuzzed<R>(mutator: &mut Mutator<R>, _: Option<&Constraints<<Self as lain::prelude::NewFuzzed>::RangeType>>) -> Self where R: Rng {
        let variant = mutator.gen_range(0, 2);
        match variant {
            0 => {
                ScalarGenerationFlags::ValidWithPropabilityOfZero(ZERO_SCALAR_PROBABILITY)
            },
            1 => {
                ScalarGenerationFlags::InvalidLength
            },
            _ => {unreachable!()}
        }
    }
}

#[derive(Derivative, Mutatable, NewFuzzed)]
#[derivative(Clone, Debug, Copy, PartialEq, Eq)]
pub enum FieldGenerationFlags {
    CreateZero,
    CreateValid,
    CreateNotInField,
    CreateOtherInvalidEncoding,
    CreateInvalidLength
}

#[derive(Derivative, Mutatable, NewFuzzed)]
#[derivative(Clone, Debug, Copy, PartialEq, Eq)]
pub enum EcPointGenerationFlag {
    CreateInfinity,
    CreateValid,
    CreateNotOnCurve,
    CreateInvalidSubgroup,
    CreateOtherInvalidEncoding,
    CreateInvalidLength
}

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct EIP2537Generator<R: Rng> {
    #[derivative(Debug="ignore")]
    marker: std::marker::PhantomData<R>
}

fn map_err_to_string<T, R: std::fmt::Debug>(prefix: &str, res: Result<T, R>) -> Result<T, String> {
    res.map_err(|err| {
        format!("{}: Error: {:?}", prefix, err)
    })
}

// fn map_result_verbose<T: AsRef<[u8]>, R: std::fmt::Debug>(res: Result<T, R>, verbose: bool) -> Result<Vec<u8>, ()> {
//     res.map_err(|err| {
//         if verbose {
//             println!("{:?}", err);
//         }

//         ()
//     }) 
//     .map(|res| {
//         if verbose {
//             println!("Got result!");
//         }
//         res.as_ref().to_vec()
//     })
// }

// fn compare_results<T: Eq, R, U>(a: Result<T, R>, b: Result<T, U>) -> Result<(), ()>{
//     match (a, b) {
//         (Ok(a), Ok(b)) => {
//             if a != b {
//                 return Err(())
//             }
//         },
//         (Ok(..), Err(..)) | (Err(..), Ok(..)) => {
//             return Err(())
//         },
//         _ => {}
//     }

//     Ok(())
// }

fn compare_multiple_structured_results<R: std::fmt::Debug>(results: &[Result<Vec<u8>, R>]) -> Result<(), String> {
    assert!(results.len() > 0);
    let reference = &results[0];
    let mut answer = String::new();

    for (idx, r) in results[1..].iter().enumerate() {
        match (reference, r) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    let _ = write!(&mut answer, "Reference result is {}, got result {} for alternative number {}", hex::encode(&a), hex::encode(&b), idx+1);
                    return Err(answer)
                }
            },
            (Ok(a), Err(e)) => {
                let _ = write!(&mut answer, "Reference result is {}, got error {:?} for alternative number {}", hex::encode(&a), e, idx+1);
                return Err(answer)
            },
            (Err(e), Ok(b)) => {
                let _ = write!(&mut answer, "Reference error is {:?}, got result {} for alternative number {}", e, hex::encode(&b), idx+1);
                return Err(answer)
            },
            _ => {}
        }
    }

    Ok(())
}

// fn compare_multiple_results<T: Eq, R>(results: &[Result<T, R>]) -> Result<(), ()> {
//     assert!(results.len() > 0);
//     let reference = &results[0];
//     for r in results[1..].iter() {
//         match (reference, r) {
//             (Ok(a), Ok(b)) => {
//                 if a != b {
//                     return Err(())
//                 }
//             },
//             (Ok(..), Err(..)) | (Err(..), Ok(..)) => {
//                 return Err(())
//             },
//             _ => {}
//         }
//     }

//     Ok(())
// }

pub fn create_runners<R: Rng>(verbose_errors: bool, verbose_results: bool) -> Vec<FuzzerTarget<R>> {
    let g1_add_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g1_add_input(mutator, context)
    };

    let g1_add_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::g1_add(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::G1ADD, &input));

        vec![rust_result, go_result]
    };

    let g1_add_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "G1ADD",
        generator: Box::new(g1_add_gen_fn) as _,
        executor: Box::new(g1_add_run_fn) as _,
    };

    let g1_mul_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g1_mul_input(mutator, context)
    };

    let g1_mul_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::g1_mul(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::G1MUL, &input));

        vec![rust_result, go_result]
    };

    let g1_mul_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "G1MUL",
        generator: Box::new(g1_mul_gen_fn) as _,
        executor: Box::new(g1_mul_run_fn) as _,
    };

    let g1_multiexp_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g1_multiexp_input(mutator, context)
    };

    let g1_multiexp_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::g1_multiexp(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::G1MULTIEXP, &input));

        vec![rust_result, go_result]
    };

    let g1_multiexp_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "G1MULTIEXP",
        generator: Box::new(g1_multiexp_gen_fn) as _,
        executor: Box::new(g1_multiexp_run_fn) as _,
    };

    let g2_add_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g2_add_input(mutator, context)
    };

    let g2_add_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::g2_add(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::G2ADD, &input));

        vec![rust_result, go_result]
    };

    let g2_add_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "G2ADD",
        generator: Box::new(g2_add_gen_fn) as _,
        executor: Box::new(g2_add_run_fn) as _,
    };

    let g2_mul_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g2_mul_input(mutator, context)
    };

    let g2_mul_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::g2_mul(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::G2MUL, &input));

        vec![rust_result, go_result]
    };

    let g2_mul_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "G2MUL",
        generator: Box::new(g2_mul_gen_fn) as _,
        executor: Box::new(g2_mul_run_fn) as _,
    };

    let g2_multiexp_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g2_multiexp_input(mutator, context)
    };

    let g2_multiexp_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::g2_multiexp(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::G2MULTIEXP, &input));

        vec![rust_result, go_result]
    };

    let g2_multiexp_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "G2MULTIEXP",
        generator: Box::new(g2_multiexp_gen_fn) as _,
        executor: Box::new(g2_multiexp_run_fn) as _,
    };

    let pairing_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_pairing_input(mutator, context)
    };

    let pairing_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::pair(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::PAIR, &input));

        vec![rust_result, go_result]
    };

    let pairing_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "PAIRING",
        generator: Box::new(pairing_gen_fn) as _,
        executor: Box::new(pairing_run_fn) as _,
    };

    let fp_map_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_fp_mapping_input(mutator, context)
    };

    let fp_map_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::map_fp_to_g1(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::MAPFPTOG1, &input));

        vec![rust_result, go_result]
    };

    let fp_map_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "FPTOG1",
        generator: Box::new(fp_map_gen_fn) as _,
        executor: Box::new(fp_map_run_fn) as _,
    };

    let fp2_map_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_fp2_mapping_input(mutator, context)
    };

    let fp2_map_run_fn = move |input: &[u8]| {
        let rust_result = map_err_to_string("Rust", EIP2537Executor::map_fp2_to_g2(input).map(|el| el.to_vec()));
        let go_result = map_err_to_string("Go",perform_operation(OperationType::MAPFP2TOG2, &input));

        vec![rust_result, go_result]
    };

    let fp2_map_target = FuzzerTarget {
        verbose_errors,
        verbose_results,
        op_name: "FP2TOG2",
        generator: Box::new(fp2_map_gen_fn) as _,
        executor: Box::new(fp2_map_run_fn) as _,
    };

    vec![
        g1_add_target, 
        g1_mul_target, 
        g1_multiexp_target,
        g2_add_target, 
        g2_mul_target, 
        g2_multiexp_target,
        pairing_target,
        fp_map_target,
        fp2_map_target
    ]
}

fn generate_g1_add_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g1_generation_fn.as_mut()(mutator, flag));

    input
}

fn generate_g1_mul_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
    let mut flag = ScalarGenerationFlags::new_fuzzed(mutator, None);
    if let ScalarGenerationFlags::ValidWithPropabilityOfZero(p) = &mut flag {
        *p = ZERO_SCALAR_PROBABILITY;
    }
    input.extend(context.scalar_generation_fn.as_mut()(mutator, flag));

    input
}

fn generate_g1_multiexp_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let num_pais = mutator.gen_range(MIN_MULTIEXP_PAIRS, MAX_MULTIEXP_PAIRS);
    let gen_all_valid = mutator.gen_chance(0.9);
    if gen_all_valid {
        for _ in 0..num_pais {
            let flag = EcPointGenerationFlag::CreateValid;
            input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
            let flag = ScalarGenerationFlags::ValidWithPropabilityOfZero(ZERO_SCALAR_PROBABILITY);
            input.extend(context.scalar_generation_fn.as_mut()(mutator, flag));

        }
    } else {
        let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
        input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
        let mut flag = ScalarGenerationFlags::new_fuzzed(mutator, None);
        if let ScalarGenerationFlags::ValidWithPropabilityOfZero(p) = &mut flag {
            *p = ZERO_SCALAR_PROBABILITY;
        }
        input.extend(context.scalar_generation_fn.as_mut()(mutator, flag));

    }

    input
}

fn generate_g2_add_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g2_generation_fn.as_mut()(mutator, flag));
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g2_generation_fn.as_mut()(mutator, flag));

    input
}

fn generate_g2_mul_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g2_generation_fn.as_mut()(mutator, flag));
    let mut flag = ScalarGenerationFlags::new_fuzzed(mutator, None);
    if let ScalarGenerationFlags::ValidWithPropabilityOfZero(p) = &mut flag {
        *p = ZERO_SCALAR_PROBABILITY;
    }
    input.extend(context.scalar_generation_fn.as_mut()(mutator, flag));

    input
}

fn generate_g2_multiexp_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let num_pais = mutator.gen_range(MIN_MULTIEXP_PAIRS, MAX_MULTIEXP_PAIRS);
    let gen_all_valid = mutator.gen_chance(0.9);
    if gen_all_valid {
        for _ in 0..num_pais {
            let flag = EcPointGenerationFlag::CreateValid;
            input.extend(context.g2_generation_fn.as_mut()(mutator, flag));
            let flag = ScalarGenerationFlags::ValidWithPropabilityOfZero(ZERO_SCALAR_PROBABILITY);
            input.extend(context.scalar_generation_fn.as_mut()(mutator, flag));

        }
    } else {
        let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
        input.extend(context.g2_generation_fn.as_mut()(mutator, flag));
        let mut flag = ScalarGenerationFlags::new_fuzzed(mutator, None);
        if let ScalarGenerationFlags::ValidWithPropabilityOfZero(p) = &mut flag {
            *p = ZERO_SCALAR_PROBABILITY;
        }
        input.extend(context.scalar_generation_fn.as_mut()(mutator, flag));

    }

    input
}

fn generate_pairing_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let num_pais = mutator.gen_range(MIN_PAIRING_PAIRS, MAX_PAIRING_PAIRS);
    let gen_all_valid = mutator.gen_chance(0.9);
    if gen_all_valid {
        for _ in 0..num_pais {
            let flag = EcPointGenerationFlag::CreateValid;
            input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
            let flag = EcPointGenerationFlag::CreateValid;
            input.extend(context.g2_generation_fn.as_mut()(mutator, flag));
        }
    } else {
        let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
        input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
        let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
        input.extend(context.g2_generation_fn.as_mut()(mutator, flag));
    }

    input
}

fn generate_fp_mapping_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let flag = FieldGenerationFlags::new_fuzzed(mutator, None);
    context.fp_generation_fn.as_mut()(mutator, flag)
}

fn generate_fp2_mapping_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let flag = FieldGenerationFlags::new_fuzzed(mutator, None);
    context.fp2_generation_fn.as_mut()(mutator, flag)
}

use eth_pairings::field::*;
use eth_pairings::weierstrass::*;
use eth_pairings::fp::*;

type Scalar = eth_pairings::integers::MaxGroupSizeUint;

type FpElement = eth_pairings::fp::Fp<'static, U384Repr, PrimeField<U384Repr>>;
type Fp2Element = eth_pairings::extension_towers::fp2::Fp2<'static, U384Repr, PrimeField<U384Repr>>;

type G1 = eth_pairings::weierstrass::curve::CurvePoint<'static, CurveOverFpParameters<'static, U384Repr, PrimeField<U384Repr>>>;
type G2 = eth_pairings::weierstrass::curve::CurvePoint<'static, CurveOverFp2Parameters<'static, U384Repr, PrimeField<U384Repr>>>;

const ZERO_SCALAR_PROBABILITY: f64 = 0.001;
const MIN_MULTIEXP_PAIRS: usize = 0;
const MAX_MULTIEXP_PAIRS: usize = 192;

const MIN_PAIRING_PAIRS: usize = 0;
const MAX_PAIRING_PAIRS: usize = 5;

const SCALAR_BYTE_LENGTH: usize = 32;
const SERIALIZED_FP_BYTE_LENGTH: usize = 64;
const SERIALIZED_FP2_BYTE_LENGTH: usize = SERIALIZED_FP_BYTE_LENGTH * 2;
const SERIALIZED_G1_POINT_BYTE_LENGTH: usize = SERIALIZED_FP_BYTE_LENGTH * 2;
const SERIALIZED_G2_POINT_BYTE_LENGTH: usize = SERIALIZED_FP2_BYTE_LENGTH * 2;

fn make_random_fp_with_encoding<R: Rng>(rng: &mut R, modulus: &BigUint) -> (FpElement, Vec<u8>) {
    let mut buff = vec![0u8; 48*3];
    rng.fill_bytes(&mut buff);

    let num = BigUint::from_bytes_be(&buff);
    let num = num % modulus.clone();

    let x = Fp::from_be_bytes(&bls12_381::BLS12_381_FIELD, &num.to_bytes_be(), true).unwrap();

    let as_vec = decode_fp::serialize_fp_fixed_len(SERIALIZED_FP_BYTE_LENGTH, &x).unwrap();

    assert!(as_vec.len() == SERIALIZED_FP_BYTE_LENGTH);
    assert_eq!(&as_vec[..16], &[0u8; 16]);

    (x, as_vec)
}

fn make_invalid_encoding_fp<R: Rng>(rng: &mut R, modulus: &BigUint, use_overflow: bool) -> Vec<u8> {
    let mut buff = vec![0u8; 48*3];
    rng.fill_bytes(&mut buff);

    let num = BigUint::from_bytes_be(&buff);
    let mut num = num % modulus.clone();

    if use_overflow {
        num += modulus;
    }

    let as_be = num.to_bytes_be();
    let mut encoding = vec![0u8; 64 - as_be.len()]; 

    if !use_overflow {
        rng.fill_bytes(&mut encoding);
    }

    encoding.extend(as_be);

    encoding
}

fn make_random_fp2_with_encoding<R: Rng>(rng: &mut R, modulus: &BigUint) -> (Fp2Element, Vec<u8>) {
    let mut encoding = Vec::with_capacity(SERIALIZED_FP2_BYTE_LENGTH);

    let (c0, c0_encoding) = make_random_fp_with_encoding(rng, &modulus);
    let (c1, c1_encoding) = make_random_fp_with_encoding(rng, &modulus);

    encoding.extend(c0_encoding);
    encoding.extend(c1_encoding);

    assert!(encoding.len() == SERIALIZED_FP2_BYTE_LENGTH);

    let mut fe = bls12_381::BLS12_381_FP2_ZERO.clone();
    fe.c0 = c0;
    fe.c1 = c1;

    (fe, encoding)
}

fn make_invalid_encoding_fp2<R: Rng>(rng: &mut R, modulus: &BigUint, use_overflow: bool) -> Vec<u8> {
    let mut encoding = Vec::with_capacity(SERIALIZED_FP2_BYTE_LENGTH);
    let invalid_c0: bool = rng.gen();
    if invalid_c0 {
        encoding.extend(make_invalid_encoding_fp(rng, modulus, use_overflow));
    } else {
        let (_, enc) = make_random_fp_with_encoding(rng, modulus);
        encoding.extend(enc);
    }
    let invalid_c1: bool = rng.gen();
    if invalid_c1 || !invalid_c0 {
        encoding.extend(make_invalid_encoding_fp(rng, modulus, use_overflow));
    } else {
        let (_, enc) = make_random_fp_with_encoding(rng, modulus);
        encoding.extend(enc);
    }
    
    encoding
}

fn encode_g1(point: &G1) -> Vec<u8> {
    let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &point).unwrap();

    assert!(as_vec.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);
    assert_eq!(&as_vec[..16], &[0u8; 16]);
    assert_eq!(&as_vec[64..80], &[0u8; 16]);

    as_vec
}

fn encode_g2(point: &G2) -> Vec<u8> {
    let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &point).unwrap();

    assert!(as_vec.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

    as_vec
}

fn make_random_g1_with_encoding<R: Rng>(rng: &mut R) -> Vec<u8> {
    let mut buff = vec![0u8; SCALAR_BYTE_LENGTH];
    rng.fill_bytes(&mut buff);

    let (scalar, _) = decode_g1::decode_scalar_representation(&buff, SCALAR_BYTE_LENGTH).unwrap();

    let mut p = bls12_381::BLS12_381_G1_GENERATOR.mul(&scalar);
    p.normalize();

    let as_vec = encode_g1(&p);

    as_vec
}

fn make_random_g2_with_encoding<R: Rng>(rng: &mut R) -> Vec<u8> {
    let mut buff = vec![0u8; SCALAR_BYTE_LENGTH];
    rng.fill_bytes(&mut buff);

    let (scalar, _) = decode_g1::decode_scalar_representation(&buff, SCALAR_BYTE_LENGTH).unwrap();

    let mut p = bls12_381::BLS12_381_G2_GENERATOR.mul(&scalar);
    p.normalize();

    let as_vec = encode_g2(&p);

    as_vec
}

fn make_random_scalar_with_encoding<R: Rng>(rng: &mut R) -> (Scalar, Vec<u8>) {
    let mut buff = vec![0u8; SCALAR_BYTE_LENGTH];
    rng.fill_bytes(&mut buff);

    let (scalar, _) = decode_g1::decode_scalar_representation(&buff, SCALAR_BYTE_LENGTH).unwrap();

    (scalar, buff)
}

fn make_g1_in_invalid_subgroup<R: Rng>(rng: &mut R) -> Vec<u8> {
    let modulus = BigUint::from_str_radix("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10).unwrap();
    let (fp, _) = make_random_fp_with_encoding(rng, &modulus);
    let one = FpElement::one(&bls12_381::BLS12_381_FIELD);

    let mut fp_candidate = fp;

    let p;

    loop {
        let mut rhs = fp_candidate.clone();
        rhs.square();
        rhs.mul_assign(&fp_candidate);
        rhs.add_assign(&bls12_381::BLS12_381_B_FOR_G1);

        let leg = legendre_symbol_fp(&rhs);
        if leg == LegendreSymbol::QuadraticResidue {
            let y = sqrt(&rhs).unwrap();
            let point = G1::point_from_xy(&bls12_381::BLS12_381_G1_CURVE, fp_candidate.clone(), y);

            if point.wnaf_mul_with_window_size(&bls12_381::BLS12_381_SUBGROUP_ORDER[..], 5).is_zero() == false {
                p = Some(point);
                break;
            }
        } else {
            fp_candidate.add_assign(&one);
        }
    }

    encode_g1(&p.unwrap())
}  

fn make_g2_in_invalid_subgroup<R: Rng>(rng: &mut R) -> Vec<u8> {
    let modulus = BigUint::from_str_radix("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10).unwrap();
    let (fp, _) = make_random_fp2_with_encoding(rng, &modulus);
    let one = Fp2Element::one(&bls12_381::BLS12_381_EXTENSION_2_FIELD);

    let mut fp_candidate = fp;

    let p;
    loop {
        let mut rhs = fp_candidate.clone();
        rhs.square();
        rhs.mul_assign(&fp_candidate);
        rhs.add_assign(&bls12_381::BLS12_381_B_FOR_G2);

        let leg = legendre_symbol_fp2(&rhs);
        if leg == LegendreSymbol::QuadraticResidue {
            let y = sqrt_ext2(&rhs).unwrap();
            let point = G2::point_from_xy(&bls12_381::BLS12_381_G2_CURVE, fp_candidate.clone(), y);

            if point.wnaf_mul_with_window_size(&bls12_381::BLS12_381_SUBGROUP_ORDER[..], 5).is_zero() == false {
                p = Some(point);
                break;
            }
        } else {
            fp_candidate.add_assign(&one);
        }
    };

    encode_g2(&p.unwrap())
}

pub fn run(verbose_errors: bool, verbose_results: bool, threads: usize) {
    let mut driver = lain::driver::FuzzerDriver::<()>::new(threads);
    driver.set_seed(42);
    let driver = std::sync::Arc::from(driver);

    let ctrlc_driver = driver.clone();
    let stop_progress = std::sync::atomic::AtomicBool::new(false);
    let stop_progress = std::sync::Arc::from(stop_progress);
    let ctrlc_driver_stop_progress = stop_progress.clone();

    ctrlc::set_handler(move || {
        ctrlc_driver_stop_progress.store(true, std::sync::atomic::Ordering::Relaxed);
        ctrlc_driver.signal_exit();
    }).expect("couldn't set CTRL-C handler");

    lain::driver::start_fuzzer(driver.clone(),
        move |mutator, _ctx: &mut (), _| {
            let mut generation_context = GenerationContext::create();
            let mut targets = create_runners(verbose_errors, verbose_results);
            let idx = mutator.gen_range(0, targets.len());
            let runner = &mut targets[idx];

            let input = runner.generate(mutator, &mut generation_context);
            let output = runner.run(&input);

            if output.is_err() {
                eprintln!("Mismatch on op {:?} with input {}, description: {}", &*runner, hex::encode(&input), output.err().unwrap());
                return Err(())
            }

            Ok(())
        }
    );

    let progress_driver = driver.clone();

    let progress_thread = std::thread::spawn(move || {
        use console::Term;
        use console::Style;

        let green = Style::new().green();
        let red = Style::new().red();

        let term = Term::stdout();
        // let term = Term::buffered_stdout();
        loop {
            let msg = format!(
                "Done {} iterations, {} failed iterations", 
                green.apply_to(format!("{}", progress_driver.num_iterations())), 
                red.apply_to(format!("{}", progress_driver.num_failed_iterations()))
            );
            let _ = term.write_line(&msg);
            std::thread::sleep(std::time::Duration::from_millis(5000));
            // let _ = term.clear_line();

            let stop = stop_progress.load(std::sync::atomic::Ordering::Relaxed);
            if stop {
                break;
            }
        }
    });

    driver.join_threads();
    progress_thread.join().unwrap();

    println!("Finished in {} iterations, {} failed iterations", driver.num_iterations(), driver.num_failed_iterations());
}

#[test]
fn test_to_check_valid_outputs() {
    run(false, true, 1);
}