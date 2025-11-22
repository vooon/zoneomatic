package zone

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	assert := assert.New(t)

	ctrl, err := New("testdata/at.example.com.zone", "testdata/mx.example.com.zone")
	if assert.NoError(err) {
		assert.Len(ctrl.(*DomainCtrl).files, 2)
	}
}
