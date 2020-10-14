pub trait FieldRandomnessSource {
    type Flags: Clone + std::fmt::Debug;

    fn can_produce_invalid_values(&self) -> bool {
        true
    }
    fn random_valid_field_element(&mut self, flags: &Self::Flags) -> Vec<u8>;
    fn random_invalid_field_element(&mut self) -> Vec<u8>;
}

pub trait GroupRandomnessSource {
    type Flags: Clone + std::fmt::Debug;

    type ScalarElementSource: FieldRandomnessSource;
    
    fn can_produce_invalid_values(&self) -> bool {
        true
    }
    fn random_valid_group_element(&mut self) -> Vec<u8>;
    fn random_invalid_group_element(&mut self) -> Vec<u8>;
}