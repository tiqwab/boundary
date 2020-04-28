package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"google.golang.org/protobuf/proto"
	"gotest.tools/assert"
)

func TestNewRoleGrant(t *testing.T) {

	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.NilError(t, err)
		assert.Check(t, g != nil)
		assert.Equal(t, g.RoleId, role.Id)
		assert.Equal(t, g.Grant, "everything*")
		err = w.Create(context.Background(), g)
		assert.NilError(t, err)
		assert.Check(t, g.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		uRole, err := NewAssignedRole(s, role, user)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetRoleId(), role.Id)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		g, err := NewRoleGrant(nil, role, "everything*")
		assert.Check(t, err != nil)
		assert.Check(t, g == nil)
		assert.Equal(t, err.Error(), "error the role grant primary scope is nil")
	})
	t.Run("nil-role", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		g, err := NewRoleGrant(s, nil, "everything*")
		assert.Check(t, err != nil)
		assert.Check(t, g == nil)
		assert.Equal(t, err.Error(), "error role is nil")
	})
}

func TestRoleGrant_Actions(t *testing.T) {
	g := &RoleGrant{}
	a := g.Actions()
	assert.Equal(t, a[ActionList.String()], ActionList)
	assert.Equal(t, a[ActionCreate.String()], ActionCreate)
	assert.Equal(t, a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(t, a[ActionEdit.String()], ActionEdit)
	assert.Equal(t, a[ActionDelete.String()], ActionDelete)
}

func TestRoleGrant_ResourceType(t *testing.T) {
	r := &RoleGrant{}
	ty := r.ResourceType()
	assert.Equal(t, ty, ResourceTypeRoleGrant)
}

func TestRoleGrant_GetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.NilError(t, err)
		assert.Check(t, g != nil)
		assert.Equal(t, g.RoleId, role.Id)
		assert.Equal(t, g.Grant, "everything*")

		ps, err := g.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, ps != nil)
		assert.Equal(t, ps.Id, s.Id)
	})
}

func TestRoleGrant_Clone(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.NilError(t, err)
		assert.Check(t, g != nil)
		assert.Equal(t, g.RoleId, role.Id)
		assert.Equal(t, g.Grant, "everything*")

		cp := g.Clone()
		assert.Check(t, proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.NilError(t, err)
		assert.Check(t, g != nil)
		assert.Equal(t, g.RoleId, role.Id)
		assert.Equal(t, g.Grant, "everything*")

		g2, err := NewRoleGrant(s, role, "nothing*")
		assert.NilError(t, err)
		assert.Check(t, g2 != nil)
		assert.Equal(t, g2.RoleId, role.Id)
		assert.Equal(t, g2.Grant, "nothing*")

		cp := g.Clone()
		assert.Check(t, !proto.Equal(cp.(*RoleGrant).RoleGrant, g2.RoleGrant))

	})
}
