help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

fmt: ## Format code
	@rustup component add --toolchain nightly rustfmt 2>/dev/null || true
	@cargo +nightly fmt --all $(if $(CHECK),-- --check,)

clippy: ## Run clippy
	@cargo clippy --features=encryption -- -D warnings

cq: ## Run code quality checks (formatting + clippy)
	@$(MAKE) fmt CHECK=1
	@$(MAKE) clippy

check: ## Type-check
	@cargo check --features=encryption

test: ## Run tests in debug and release profiles
	@cargo test --features=encryption
	@cargo test --release --features=encryption
	@cargo check --manifest-path tests/zeroize-compat/Cargo.toml

no-std: ## Verify no_std compatibility on bare-metal target
	@rustup target add thumbv6m-none-eabi 2>/dev/null || true
	@cargo build --no-default-features --target thumbv6m-none-eabi

doc: ## Generate docs
	@cargo doc --no-deps --features=encryption

clean: ## Clean build artifacts
	@cargo clean

.PHONY: help fmt clippy cq check test no-std doc clean
