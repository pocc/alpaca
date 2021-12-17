# Run the main script
.PHONY: build clean suffixes

clean:
	rm -rf build

build: clean
	tsc && cp manifest.json media/orange* src/*.css build
# Delete export lines that ES5 chrome can't understand
	sd 'export \{\};\n' '' ./build/*.js

release: build
	zip waypost.zip build/*
