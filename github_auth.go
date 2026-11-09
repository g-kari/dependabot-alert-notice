package main

import (
	"errors"
	"flag"
	"log/slog"
	"os"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
	"github.com/g-kari/dependabot-alert-notice/internal/updater"
)

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func loadUpdateConfig(path string, allowMissingDefault bool) (*config.Config, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissingDefault {
		return config.Defaults(), nil
	}
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}

func releaseSource(repository, path string, cfg config.Config) (updater.GitHubSource, error) {
	if path == "" {
		path = cfg.GhPath
	}
	return updater.NewGitHubSource(repository, path, cfg.GitHubAuth)
}

func warnInheritedGitHub(settings ghcommand.Settings) {
	if settings.Mode == "" || settings.Mode == "inherited" {
		slog.Warn("GitHub authentication: inherited legacy console context; configure github_auth.mode=token_env for explicit authentication")
	}
}
