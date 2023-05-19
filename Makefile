# Run the main script
.PHONY: build clean suffixes

clean:
	rm -rf build

build: clean
	tsc && cp manifest.json media/orange* src/*.css build
# Delete export lines that ES5 chrome can't understand
	sd 'export \{\};\n' '' ./build/*.js

mock_release: build
	sd '.*if \(DEBUG\).*' '' ./build/*.js
	sd '.*console\..*' '' ./build/*.js

release: mock_release
	zip alpaca.zip build/*
