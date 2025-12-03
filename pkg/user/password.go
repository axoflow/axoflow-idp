// Copyright © 2025 Axoflow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package user

import "golang.org/x/crypto/argon2"

const (
	time    = 2
	memory  = 15 * 1024
	threads = 1
	keyLen  = 32
)

func hash(salt []byte, password string) []byte {
	return argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
}
