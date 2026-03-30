package fflags

import (
	"context"
	"fmt"

	"github.com/thomaspoignant/go-feature-flag/ffcontext"
	"github.com/thomaspoignant/go-feature-flag/modules/core/dto"
	"github.com/thomaspoignant/go-feature-flag/modules/core/flag"
)

// ServingStatus represents the current serving state of a service.
type ServingStatus string

// String returns the string representation of the ServingStatus.
func (s ServingStatus) String() string {
	return string(s)
}

// StringP returns a pointer to the string representation of the ServingStatus.
func (s ServingStatus) StringP() *string {
	str := string(s)
	return &str
}

const (
	METADATA_KIND         = "kind"
	SERVING_METADATA_KIND = "operational-serving"
	SERVING_FLAG_SUFFIX   = "serving"

	SERVING_STATUS_SERVING     ServingStatus = "serving"
	SERVING_STATUS_NOT_SERVING ServingStatus = "not-serving"
)

// IsServing returns true if the specified service is currently serving traffic.
func (m *Manager) IsServing(ctx context.Context, service string) (bool, error) {
	flagName := fmt.Sprintf("%s-%s", service, SERVING_FLAG_SUFFIX)
	return m.client.BoolVariation(flagName, ffcontext.NewEvaluationContext("operational"), false)
}

// GetServing retrieves the ServingStatus for the specified service.
func (m *Manager) GetServing(ctx context.Context, service string) (ServingStatus, error) {
	status, err := m.IsServing(ctx, service)
	if status {
		return SERVING_STATUS_SERVING, err
	}
	return SERVING_STATUS_NOT_SERVING, err
}

// SetServing updates the ServingStatus for an existing service, altering its serving state.
func (m *Manager) SetServing(ctx context.Context, service string, status ServingStatus) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	flags, err := m.loadFlags(ctx)
	if err != nil {
		return err
	}

	flagName := fmt.Sprintf("%s-%s", service, SERVING_FLAG_SUFFIX)

	flag, exists := flags[flagName]
	if !exists {
		return fmt.Errorf("flag %s not found", flagName)
	}

	if err := m.validateServingFlag(ctx, flag); err != nil {
		return err
	}

	flag.DefaultRule.VariationResult = status.StringP()

	return m.storeFlags(ctx, flags)
}

// CreateServing initializes a new serving flag for the specified service with the given status.
func (m *Manager) CreateServing(ctx context.Context, service string, status ServingStatus) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	flags, err := m.loadFlags(ctx)
	if err != nil {
		return err
	}

	flagName := fmt.Sprintf("%s-%s", service, SERVING_FLAG_SUFFIX)

	if _, exists := flags[flagName]; exists {
		return fmt.Errorf("flag %s already exists", flagName)
	}

	var (
		trueAny  = any(true)
		falseAny = any(false)
		falseVal = false
	)
	flag := dto.DTO{
		Metadata: &map[string]any{
			METADATA_KIND: SERVING_METADATA_KIND,
		},
		Variations: &map[string]*any{
			string(SERVING_STATUS_SERVING):     &trueAny,
			string(SERVING_STATUS_NOT_SERVING): &falseAny,
		},
		DefaultRule: &flag.Rule{
			VariationResult: status.StringP(),
		},
		TrackEvents: &falseVal,
	}

	if err := m.validateServingFlag(ctx, flag); err != nil {
		return err
	}

	flags[flagName] = flag
	return m.storeFlags(ctx, flags)
}

// DeleteServing permanently removes the serving flag for the specified service.
func (m *Manager) DeleteServing(ctx context.Context, service string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	flags, err := m.loadFlags(ctx)
	if err != nil {
		return err
	}

	flagName := fmt.Sprintf("%s-%s", service, SERVING_FLAG_SUFFIX)

	if _, exists := flags[flagName]; !exists {
		return fmt.Errorf("flag %s not found", flagName)
	}

	delete(flags, flagName)

	return m.storeFlags(ctx, flags)
}

func (m *Manager) validateServingFlag(ctx context.Context, flag dto.DTO) error {
	if flag.Metadata == nil {
		return fmt.Errorf("flag has no metadata")
	}
	kind, ok := (*flag.Metadata)[METADATA_KIND]
	if !ok {
		return fmt.Errorf("flag has no kind metadata")
	}

	if kind != SERVING_METADATA_KIND {
		return fmt.Errorf("flag is not of kind %s", SERVING_METADATA_KIND)
	}
	return nil
}
