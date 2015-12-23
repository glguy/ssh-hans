.PHONY: build-all-platforms
build-all-platforms:
	@echo ================================================================
	stack --stack-yaml=stack.ghc-7.8.yaml build
	@echo
	@echo ================================================================
	stack --stack-yaml=stack.ghc-7.10.yaml build

.PHONY: haddock-all-platforms
haddock-all-platforms:
	@echo ================================================================
	stack --stack-yaml=stack.ghc-7.8.yaml haddock
	@echo
	@echo ================================================================
	stack --stack-yaml=stack.ghc-7.10.yaml haddock
