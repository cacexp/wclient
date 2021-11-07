# Rust Web Client (wclient)

`wclient` is lightweigh HTTP client inspired in [Python Requests](https://docs.python-requests.org/en/latest/) and written in Rust.

This is the first MVP implementation supporting HTTP and basic HTTPS just to test the API and the its viability.

[How to run the tests](testing.md)

'wclient' uses:
*[rustls](https://crates.io/crates/rustls)
*[json](https://crates.io/crates/json)
*[url](https://crates.io/crates/url)
*[log](https://crates.io/crates/log)
*[chrono](https://crates.io/crates/chrono)
*[case_insensitive_hashmap](https://crates.io/crates/case_insensitive_hashmap)

# Contributions

This development is in an early stage. I appreciate you interest and welcome any comment, bug, idea, etc.

When having an stable baseline, I will consider to receive code contributions as Pull-Requests.

Please, use the [GitHub Issues](https://github.com/cacexp/wclient/issues) to provide feedback.

# License

Copyright 2021 Juan A. Cáceres (cacexp@gmail.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.