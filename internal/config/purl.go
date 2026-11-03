package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/model"
)

// purl 型別 → OSV ecosystem 的對照（規劃 §3.1 的 purl 簡寫支援）。
var purlTypeToEcosystem = map[string]string{
	"golang": model.EcosystemGo,
	"cargo":  model.EcosystemCrates,
	"pypi":   model.EcosystemPyPI,
	"npm":    model.EcosystemNPM,
	"maven":  model.EcosystemMaven,
	"nuget":  model.EcosystemNuGet,
}

// ParsePurl 解析 purl 簡寫，例如：
//
//	pkg:golang/golang.org/x/net@v0.20.0
//	pkg:pypi/requests@2.31.0
//	pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
//
// 回傳 ecosystem、name、version。
func ParsePurl(s string) (ecosystem, name, version string, err error) {
	raw := strings.TrimSpace(s)
	if !strings.HasPrefix(raw, "pkg:") {
		return "", "", "", fmt.Errorf("purl 必須以 pkg: 開頭: %q", s)
	}
	raw = strings.TrimPrefix(raw, "pkg:")

	// 去掉 qualifier 與 subpath，本工具用不到。
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}

	// version 在最後一個 @ 之後；但 npm scope 的 @ 在開頭，所以用 LastIndex。
	if i := strings.LastIndex(raw, "@"); i > 0 {
		version = raw[i+1:]
		raw = raw[:i]
	}

	typ, rest, ok := strings.Cut(raw, "/")
	if !ok || rest == "" {
		return "", "", "", fmt.Errorf("purl 缺少套件名稱: %q", s)
	}
	eco, ok := purlTypeToEcosystem[strings.ToLower(typ)]
	if !ok {
		return "", "", "", fmt.Errorf("purl 型別 %q 不支援（支援：golang/cargo/pypi/npm/maven/nuget）", typ)
	}

	// 各段需要 percent-decode（例如 Go module 的 / 可能被編碼成 %2F）。
	segs := strings.Split(rest, "/")
	for i, seg := range segs {
		dec, derr := url.PathUnescape(seg)
		if derr != nil {
			return "", "", "", fmt.Errorf("purl 名稱無法解碼: %q", s)
		}
		segs[i] = dec
	}

	switch eco {
	case model.EcosystemMaven:
		// maven 的 namespace 是 groupId，name 是 artifactId。
		if len(segs) < 2 {
			return "", "", "", fmt.Errorf("maven purl 需要 groupId/artifactId: %q", s)
		}
		name = strings.Join(segs[:len(segs)-1], ".") + ":" + segs[len(segs)-1]
	case model.EcosystemNPM:
		// scope 在 purl 中是 namespace：pkg:npm/%40angular/core → @angular/core
		name = strings.Join(segs, "/")
		if len(segs) == 2 && !strings.HasPrefix(segs[0], "@") {
			name = "@" + segs[0] + "/" + segs[1]
		}
	default:
		// Go module path 可能有多段；其餘生態系只有一段。
		name = strings.Join(segs, "/")
	}

	if dec, derr := url.PathUnescape(version); derr == nil {
		version = dec
	}
	return eco, name, version, nil
}
