package client

import (
	"fmt"
	"strings"
)

// ResolveGroup zwraca węzeł drzewa (workspace root albo subgrupę) dla danej
// ścieżki full_path, np. "acme" albo "acme/infra/prod" — współdzielone
// przez `sharqey ls`/`get` (cmd/cli) i terraform-provider-sharqey,
// żeby oba adresowały grupy identycznie.
func (c *Client) ResolveGroup(path string) (GroupNode, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return GroupNode{}, fmt.Errorf("empty path")
	}
	rootSlug := strings.SplitN(path, "/", 2)[0]

	root, err := c.resolveRootWorkspace(rootSlug)
	if err != nil {
		return GroupNode{}, err
	}

	tree, err := c.GroupTree(root.FullPath)
	if err != nil {
		return GroupNode{}, fmt.Errorf("group tree: %w", err)
	}
	for _, n := range tree {
		if n.FullPath == path {
			return n, nil
		}
	}
	if path == root.FullPath {
		return GroupNode{ID: root.ID, Slug: root.Slug, Name: root.Name, FullPath: root.FullPath, Depth: 0}, nil
	}
	return GroupNode{}, fmt.Errorf("unknown group %q", path)
}

// OrgIDForPath — root workspace ID dla ścieżki grupy (org identity keys są
// keyowane po ID ROOT grupy, nigdy po ID subgrupy — patrz
// project_org_independent_keys_per_org w pamięci projektu). Dla ścieżki
// będącej samym rootem to po prostu ResolveGroup(path).ID, ale wołający
// (np. terraform-provider-sharqey) nie musi znać tej różnicy.
func (c *Client) OrgIDForPath(fullPath string) (string, error) {
	rootSlug := strings.SplitN(strings.Trim(fullPath, "/"), "/", 2)[0]
	root, err := c.resolveRootWorkspace(rootSlug)
	if err != nil {
		return "", err
	}
	return root.ID, nil
}

// resolveRootWorkspace — ListWorkspaces (org root membership, ludzie) z
// fallbackiem na ServiceAccountSelf: service accounty (tasks/029) NIGDY nie
// są membershipem org roota (tylko subgrupy, patrz
// internal/serviceaccount.Handler.Create), więc ListWorkspaces zawsze
// zwróci dla nich pustą listę — bez tego fallbacku żaden CLI-owy dostęp do
// sekretów po service-account loginie nie mógłby w ogóle rozwiązać ścieżki
// grupy do organizacji. ServiceAccountSelf zwraca 404 (zignorowane tu) dla
// zwykłej sesji człowieka, więc nie ma ryzyka fałszywego dopasowania.
func (c *Client) resolveRootWorkspace(rootSlug string) (Workspace, error) {
	workspaces, err := c.ListWorkspaces()
	if err != nil {
		return Workspace{}, fmt.Errorf("list workspaces: %w", err)
	}
	for _, w := range workspaces {
		if w.FullPath == rootSlug {
			return w, nil
		}
	}
	if self, err := c.ServiceAccountSelf(); err == nil && self.OrgFullPath == rootSlug {
		return Workspace{ID: self.OrgID, Slug: self.OrgSlug, Name: self.OrgName, FullPath: self.OrgFullPath}, nil
	}
	return Workspace{}, fmt.Errorf("unknown organization %q", rootSlug)
}
