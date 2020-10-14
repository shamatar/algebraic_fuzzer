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
use std::sync::*;

pub struct GenerationContext<R: Rng> {
    pub fp_generation_fn: Box<dyn Fn(&mut Mutator<R>, FieldGenerationFlags) -> Vec<u8> + Send + Sync + 'static>,
    pub fp2_generation_fn: Box<dyn Fn(&mut Mutator<R>, FieldGenerationFlags) -> Vec<u8> + Send + Sync + 'static>,
    pub g1_generation_fn: Box<dyn Fn(&mut Mutator<R>, EcPointGenerationFlag) -> Vec<u8> + Send + Sync + 'static>,
    pub g2_generation_fn: Box<dyn Fn(&mut Mutator<R>, EcPointGenerationFlag) -> Vec<u8> + Send + Sync + 'static>,
}

impl<R: Rng> GenerationContext<R> {
    pub fn create() -> Self {
        let modulus = BigUint::from_str_radix("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10).unwrap();

        let m = modulus.clone();
        let fp_generation_fn = move |mutator: &mut Mutator<R>, flags: FieldGenerationFlags| {
            match flags {
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
            }
        };

        let m = modulus.clone();
        let fp2_generation_fn = move |mutator: &mut Mutator<R>, flags: FieldGenerationFlags| {
            match flags {
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
            }
        };

        let m = modulus.clone();
        let g1_generation_fn = move |mutator: &mut Mutator<R>, flags: EcPointGenerationFlag| {
            match flags {
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
            }
        };

        let m = modulus.clone();
        let g2_generation_fn = move |mutator: &mut Mutator<R>, flags: EcPointGenerationFlag| {
            match flags {
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
                }
            }
        };

        Self {
            fp_generation_fn: Box::new(fp_generation_fn) as _,
            fp2_generation_fn: Box::new(fp2_generation_fn) as _,
            g1_generation_fn: Box::new(g1_generation_fn) as _,
            g2_generation_fn: Box::new(g2_generation_fn) as _,
        }
    }
}

pub struct FuzzerTarget<R: Rng> {
    pub generator: Box<dyn Fn(&[u8], &mut Mutator<R>, &mut GenerationContext<R>) -> Vec<u8> + Send + Sync + 'static>,
    pub executor: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, ()> + Send + Sync + 'static>,
}

impl<R: Rng> FuzzerTarget<R> {
    pub fn generate(&mut self, mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
        self.generator.as_mut()(&[], mutator, context)
    }
    pub fn run(&self, input: &[u8]) -> Result<Vec<u8>, ()> {
        self.executor.as_ref()(input)
    }
}

#[derive(Derivative, Mutatable, NewFuzzed)]
#[derivative(Clone, Debug, Copy, PartialEq, Eq)]
pub enum FieldGenerationFlags {
    CreateValid,
    CreateNotInField,
    CreateOtherInvalidEncoding
}

#[derive(Derivative, Mutatable, NewFuzzed)]
#[derivative(Clone, Debug, Copy, PartialEq, Eq)]
pub enum EcPointGenerationFlag {
    CreateValid,
    CreateNotOnCurve,
    CreateInvalidSubgroup,
    CreateOtherInvalidEncoding
}

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct EIP2537Generator<R: Rng> {
    #[derivative(Debug="ignore")]
    marker: std::marker::PhantomData<R>
}

pub fn create_runners<R: Rng>(verbose: bool) -> Vec<FuzzerTarget<R>> {
    let g1_add_gen_fn = |_prelude: &[u8], mutator: &mut Mutator<R>, context: &mut GenerationContext<R>| {
        generate_g1_add_input(mutator, context)
    };

    let g1_add_run_fn = |input: &[u8]| {
        EIP2537Executor::g1_add(input).map_err(|err| {
            if verbose {
                println!("{}", err);
            }

            ()
        }) 
        .map(|res| {
            if verbose {
                println!("Got result!");
            }
            res.to_vec()
        })
    };

    let g1_add_target = FuzzerTarget {
        generator: Box::new(g1_add_gen_fn) as _,
        executor: Box::new(g1_add_run_fn) as _,
    };

    vec![g1_add_target]
}

fn generate_g1_add_input<R: Rng>(mutator: &mut Mutator<R>, context: &mut GenerationContext<R>) -> Vec<u8> {
    let mut input = vec![];
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g1_generation_fn.as_mut()(mutator, flag));
    let flag = EcPointGenerationFlag::new_fuzzed(mutator, None);
    input.extend(context.g1_generation_fn.as_mut()(mutator, flag));

    input
}

use eth_pairings::field::*;
use eth_pairings::weierstrass::*;
use eth_pairings::fp::*;

type Scalar = eth_pairings::integers::MaxGroupSizeUint;

type FpElement = eth_pairings::fp::Fp<'static, U384Repr, PrimeField<U384Repr>>;
type Fp2Element = eth_pairings::extension_towers::fp2::Fp2<'static, U384Repr, PrimeField<U384Repr>>;

type G1 = eth_pairings::weierstrass::curve::CurvePoint<'static, CurveOverFpParameters<'static, U384Repr, PrimeField<U384Repr>>>;
type G2 = eth_pairings::weierstrass::curve::CurvePoint<'static, CurveOverFp2Parameters<'static, U384Repr, PrimeField<U384Repr>>>;

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

fn make_random_scalar_with_encoding<R: Rng>(rng: &mut R) -> Vec<u8> {
    let mut buff = vec![0u8; SCALAR_BYTE_LENGTH];
    rng.fill_bytes(&mut buff);

    let (scalar, _) = decode_g1::decode_scalar_representation(&buff, SCALAR_BYTE_LENGTH).unwrap();

    buff
}

fn make_g1_in_invalid_subgroup<R: Rng>(rng: &mut R) -> Vec<u8> {
    let modulus = BigUint::from_str_radix("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10).unwrap();
    let (fp, _) = make_random_fp_with_encoding(rng, &modulus);
    let one = FpElement::one(&bls12_381::BLS12_381_FIELD);

    let mut fp_candidate = fp;

    let mut p = None;

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

    let mut p = None;
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

#[test]
fn test_g1_addition() {
    let driver = lain::driver::FuzzerDriver::<()>::new(4);
    let driver = std::sync::Arc::from(driver);

    let ctrlc_driver = driver.clone();

    ctrlc::set_handler(move || {
        ctrlc_driver.signal_exit();
    }).expect("couldn't set CTRL-C handler");

    lain::driver::start_fuzzer(driver.clone(),
        move |mutator, _ctx: &mut (), _| {
            let mut generation_context = GenerationContext::create();
            let mut targets = create_runners(true);
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