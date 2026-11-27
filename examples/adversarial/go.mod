// Baysöz Labs <baysozlabs@proton.me> — adversarial demonstration manifest.
module example.com/demo

go 1.24

require (
	github.com/google/uuid v1.6.0
	github.com/pkg/errors v0.9.1
)

replace github.com/pkg/errors => github.com/attacker/errors v0.9.2
