// Copyright © 2026 Axoflow
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

import (
	"slices"
	"testing"
)

func TestAdminUpdateUserGroups_SelfDemotion(t *testing.T) {
	tests := []struct {
		name     string
		adminID  string
		targetID string
		groups   []string
		wantErr  bool
	}{
		{
			name:     "removing own admin group is rejected",
			adminID:  "admin1",
			targetID: "admin1",
			groups:   []string{RoleUser},
			wantErr:  true,
		},
		{
			name:     "updating own groups keeping admin is allowed",
			adminID:  "admin1",
			targetID: "admin1",
			groups:   []string{RoleUser, "admins", "extra"},
			wantErr:  false,
		},
		{
			name:     "demoting another admin is allowed",
			adminID:  "admin1",
			targetID: "admin2",
			groups:   []string{RoleUser},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeUsersFile(t, `[
				{"ID":"admin1","Username":"alice","Groups":["admins"]},
				{"ID":"admin2","Username":"bob","Groups":["admins"]}
			]`)
			u, err := New(Config{FilePath: path, UserAdminGroup: "admins"})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			err = u.AdminUpdateUserGroups(tt.adminID, tt.targetID, tt.groups)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AdminUpdateUserGroups error = %v, wantErr %v", err, tt.wantErr)
			}

			target, _ := u.Get(tt.targetID)
			if tt.wantErr {
				if !slices.Contains(target.Groups, "admins") {
					t.Errorf("groups changed despite error: %v", target.Groups)
				}
				return
			}
			if !slices.Equal(target.Groups, tt.groups) {
				t.Errorf("groups = %v, want %v", target.Groups, tt.groups)
			}
		})
	}
}
