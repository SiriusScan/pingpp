package fingerprint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SiriusScan/ping++/pkg/model"
)

type claimIdentity struct {
	subject   string
	kind      model.ClaimKind
	vendor    string
	product   string
	family    string
	attribute string
	value     string
}

func identityOf(c model.Claim) claimIdentity {
	product := strings.ToLower(strings.TrimSpace(c.Product))
	value := strings.ToLower(strings.TrimSpace(c.Value))
	if value == product {
		value = ""
	}
	return claimIdentity{
		subject:   c.Subject,
		kind:      c.Kind,
		vendor:    strings.ToLower(strings.TrimSpace(c.Vendor)),
		product:   product,
		family:    strings.ToLower(strings.TrimSpace(c.Family)),
		attribute: strings.ToLower(strings.TrimSpace(c.Attribute)),
		value:     value,
	}
}

// Compose normalizes OS evidence, fuses claims, and records contradictions.
// Raw OS candidates do not appear in the result separately from the fused set.
func Compose(claims []model.Claim) []model.Claim {
	if len(claims) == 0 {
		return nil
	}
	var osRaw, other []model.Claim
	for _, c := range claims {
		if c.Kind == model.ClaimOS {
			osRaw = append(osRaw, c)
			continue
		}
		other = append(other, c)
	}
	fused := Fuse(other)
	fused = append(fused, FuseOS(osRaw)...)
	fused = markOSContradictions(fused)
	sort.Slice(fused, func(i, j int) bool { return fused[i].Score > fused[j].Score })
	return fused
}

// Fuse applies correlation-group combination within a subject-aware identity.
// Product identity ignores Version. Conflicting versions remain separate
// candidates and are marked contradicted.
func Fuse(claims []model.Claim) []model.Claim {
	if len(claims) == 0 {
		return nil
	}

	type keyed struct {
		claimIdentity
		cg string
	}
	best := map[keyed]model.Claim{}
	for _, c := range claims {
		k := keyed{claimIdentity: identityOf(c), cg: c.CorrelationGroup}
		if prev, ok := best[k]; !ok || c.Score > prev.Score {
			best[k] = c
		}
	}

	groups := map[claimIdentity][]model.Claim{}
	for k, c := range best {
		groups[k.claimIdentity] = append(groups[k.claimIdentity], c)
	}

	var out []model.Claim
	for _, list := range groups {
		sort.Slice(list, func(i, j int) bool { return list[i].Score > list[j].Score })
		combined := combineGroup(list)
		out = append(out, splitVersions(combined, list)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func combineGroup(list []model.Claim) model.Claim {
	combined := list[0]
	s := 1.0
	var evidence []string
	var rules []string
	var contradictions []string
	for _, c := range list {
		p := c.Score
		if p > 1 {
			p = p / 100
		}
		s *= (1 - p)
		evidence = append(evidence, c.EvidenceIDs...)
		rules = append(rules, c.RuleIDs...)
		contradictions = append(contradictions, c.ContradictionIDs...)
	}
	combined.Score = (1 - s) * 100
	combined.Confidence = model.TierFromScore(combined.Score)
	combined.EvidenceIDs = unique(evidence)
	combined.RuleIDs = unique(rules)
	combined.ContradictionIDs = unique(contradictions)
	return combined
}

func splitVersions(combined model.Claim, list []model.Claim) []model.Claim {
	bestVer := map[string]model.Claim{}
	for _, c := range list {
		v := strings.TrimSpace(c.Version)
		if v == "" {
			continue
		}
		if prev, ok := bestVer[v]; !ok || c.Score > prev.Score {
			bestVer[v] = c
		}
	}
	if len(bestVer) <= 1 {
		if len(bestVer) == 1 {
			for v := range bestVer {
				combined.Version = v
			}
		}
		return []model.Claim{combined}
	}

	combined.Version = ""
	out := []model.Claim{combined}
	var ids []string
	var candidates []model.Claim
	for v, src := range bestVer {
		vc := src
		if vc.ID == "" {
			vc.ID = fmt.Sprintf("%s:version:%s", combined.ID, v)
		} else if !strings.Contains(vc.ID, ":version:") {
			vc.ID = src.ID + ":version:" + v
		}
		vc.Version = v
		vc.Product = firstNonEmpty(vc.Product, combined.Product)
		vc.Kind = combined.Kind
		vc.Subject = combined.Subject
		vc.Attribute = "version"
		candidates = append(candidates, vc)
		ids = append(ids, vc.ID)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Version < candidates[j].Version })
	sort.Strings(ids)
	for i := range candidates {
		var others []string
		for _, id := range ids {
			if id != candidates[i].ID {
				others = append(others, id)
			}
		}
		candidates[i].ContradictionIDs = unique(append(candidates[i].ContradictionIDs, others...))
		out = append(out, candidates[i])
	}
	return out
}

func markOSContradictions(claims []model.Claim) []model.Claim {
	type idx struct {
		i        int
		priority int
	}
	bySubject := map[string][]idx{}
	for i, c := range claims {
		if c.Kind != model.ClaimOS {
			continue
		}
		bySubject[c.Subject] = append(bySubject[c.Subject], idx{i: i, priority: osPriority(c)})
	}
	for _, group := range bySubject {
		if len(group) < 2 {
			continue
		}
		best := group[0]
		for _, g := range group[1:] {
			if g.priority > best.priority || (g.priority == best.priority && claims[g.i].Score > claims[best.i].Score) {
				best = g
			}
		}
		bestFam := osFamily(claims[best.i])
		for _, g := range group {
			if g.i == best.i {
				continue
			}
			if osFamily(claims[g.i]) == bestFam {
				continue
			}
			claims[g.i].ContradictionIDs = unique(append(claims[g.i].ContradictionIDs, claims[best.i].ID))
			claims[best.i].ContradictionIDs = unique(append(claims[best.i].ContradictionIDs, claims[g.i].ID))
			if claims[g.i].Score > 55 {
				claims[g.i].Score = 55
				claims[g.i].Confidence = model.TierFromScore(55)
			}
		}
	}
	return claims
}

func osFamily(c model.Claim) string {
	f := strings.ToLower(strings.TrimSpace(c.Family))
	if f != "" {
		return f
	}
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(c.Product, c.Value)))
}

func osPriority(c model.Claim) int {
	src := strings.ToLower(strings.Join(c.RuleIDs, " ") + " " + c.CorrelationGroup)
	switch {
	case strings.Contains(src, "smb") || strings.Contains(src, "ntlm"):
		return 100
	case strings.Contains(src, "ldap"):
		return 90
	case strings.Contains(src, "snmp"):
		return 80
	case strings.Contains(src, "rdp"):
		return 70
	case strings.Contains(src, "ssh") && !isGenericOpenSSH(c):
		return 60
	case strings.Contains(src, "ssh"):
		return 40
	case strings.Contains(src, "http"):
		return 30
	case strings.Contains(src, "tcp") || strings.Contains(src, "stack"):
		return 20
	case strings.Contains(src, "ttl"):
		return 10
	case strings.Contains(src, "port"):
		return 5
	default:
		return 50
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
