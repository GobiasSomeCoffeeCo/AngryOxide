use std::fmt;

#[derive(Debug)]
pub enum AttackRate {
    Slow,
    Normal,
    Fast,
}

impl fmt::Display for AttackRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AttackRate::Slow => "Slow",
                AttackRate::Normal => "Normal",
                AttackRate::Fast => "Fast",
            }
        )
    }
}

impl AttackRate {
    pub fn to_rate(&self) -> u32 {
        match self {
            AttackRate::Slow => 200,
            AttackRate::Normal => 100,
            AttackRate::Fast => 40,
        }
    }

    pub fn from_u8(rate: u8) -> Self {
        match rate {
            1 => AttackRate::Slow,
            2 => AttackRate::Normal,
            3 => AttackRate::Fast,
            _ => AttackRate::Normal,
        }
    }
}
