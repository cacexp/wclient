// Copyright 2021 Juan A. Cáceres (cacexp@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTP configuration settings
//! 
//! Current configuration settings:
//! * `timeout`: Sets the [Duration](std::time::Duration) for a connect, read or write operation at a TCP socket
//!  

use std::time::Duration;

/// HTTP Configuration
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpConfig {
    /// Connecton, write and read timeout for a TCP socket
    pub timeout: Option<Duration>
}

/// `HttpConfig` helper builder
pub struct HttpConfigBuilder {
    pub timeout: Option<Duration>
}

impl HttpConfigBuilder {
    pub fn default() -> HttpConfigBuilder {
        HttpConfigBuilder{
            timeout: None
        }
    }

    /// Sets the connection, write and read timeout for a TCP socket
    pub fn timeout(mut self, duration: Duration) -> HttpConfigBuilder {
        self.timeout = Some(duration);
        self
    }

    /// Builder function ofor HttpConfig
    pub fn build(self) -> HttpConfig {
        HttpConfig{
            timeout: self.timeout
        }
    }
}