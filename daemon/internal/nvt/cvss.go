// Package nvt builds the NVT OID → metadata map (PLAN §10.3): name,
// family, CVEs, CVSS and QoD for every VT that produced a result, fetched
// over OSP and cached per feed version.
package nvt

import (
	"math"
	"strings"
)

// ScoreV2 computes a CVSS v2 base score from a vector such as
// "AV:N/AC:L/Au:N/C:C/I:C/A:C". Returns 0 for an unparsable vector.
func ScoreV2(vector string) float64 {
	m := parseVector(vector)
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}[m["AU"]]
	cia := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	c, okC := cia[m["C"]]
	i, okI := cia[m["I"]]
	a, okA := cia[m["A"]]
	if av == 0 || ac == 0 || au == 0 || !okC || !okI || !okA {
		return 0
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	expl := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	return round1((0.6*impact + 0.4*expl - 1.5) * f)
}

// ScoreV3 computes a CVSS v3.0/3.1 base score from a vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". Returns 0 if unparsable.
func ScoreV3(vector string) float64 {
	m := parseVector(vector)
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	changed := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, okC := cia[m["C"]]
	i, okI := cia[m["I"]]
	a, okA := cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !okC || !okI || !okA || (m["S"] != "U" && m["S"] != "C") {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10))
	}
	return roundUp(math.Min(impact+expl, 10))
}

// Score picks v3 when available, else v2, else the feed's own base score.
func Score(v3, v2 string, base float64) float64 {
	if s := ScoreV3(v3); s > 0 {
		return s
	}
	if s := ScoreV2(v2); s > 0 {
		return s
	}
	return base
}

func parseVector(v string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(v), "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[strings.ToUpper(kv[0])] = strings.ToUpper(kv[1])
		}
	}
	return m
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// roundUp is the CVSS v3.1 Roundup: smallest one-decimal value ≥ f,
// computed on integers to avoid floating-point artefacts.
func roundUp(f float64) float64 {
	i := int(math.Round(f * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
