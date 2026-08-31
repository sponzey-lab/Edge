//! Legacy HTTP-01 challenge token state behind typed application ports.

use std::collections::BTreeMap;

use edge_domain::AppError;
use edge_ports::{
    AcmeHttp01ChallengeRuntime, Http01ChallengeProbe, Http01ChallengeResponder,
    Http01ChallengeStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01Token {
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Http01TokenStore {
    tokens: BTreeMap<String, String>,
}

impl Http01TokenStore {
    pub fn insert(&mut self, token: Http01Token) {
        self.tokens.insert(token.token, token.key_authorization);
    }

    pub fn respond(&self, token: &str) -> Option<&str> {
        self.tokens.get(token).map(String::as_str)
    }

    pub fn clear(&mut self, token: &str) {
        self.tokens.remove(token);
    }
}

impl Http01ChallengeResponder for Http01TokenStore {
    fn respond(&self, token: &str) -> Option<String> {
        self.tokens.get(token).cloned()
    }
}

impl Http01ChallengeStore for Http01TokenStore {
    fn insert_http01(&mut self, token: String, key_authorization: String) -> Result<(), AppError> {
        self.insert(Http01Token {
            token,
            key_authorization,
        });
        Ok(())
    }

    fn clear_http01(&mut self, token: &str) -> Result<(), AppError> {
        self.clear(token);
        Ok(())
    }
}

pub struct Http01ChallengeRuntime<'a, T, P>
where
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    challenges: &'a mut T,
    probe: &'a mut P,
    presented_tokens: Vec<String>,
}

impl<'a, T, P> Http01ChallengeRuntime<'a, T, P>
where
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    pub fn new(challenges: &'a mut T, probe: &'a mut P) -> Self {
        Self {
            challenges,
            probe,
            presented_tokens: Vec::new(),
        }
    }

    pub fn clear_presented_http01(&mut self) -> Result<(), AppError> {
        let mut first_error = None;
        for token in std::mem::take(&mut self.presented_tokens) {
            if let Err(error) = self.challenges.clear_http01(&token) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<T, P> AcmeHttp01ChallengeRuntime for Http01ChallengeRuntime<'_, T, P>
where
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    fn present_http01(&mut self, token: String, key_authorization: String) -> Result<(), AppError> {
        self.challenges
            .insert_http01(token.clone(), key_authorization)?;
        self.presented_tokens.push(token);
        Ok(())
    }

    fn verify_http01(
        &mut self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), AppError> {
        self.probe.verify_http01(token, expected_key_authorization)
    }
}
