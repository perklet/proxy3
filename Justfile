build:
    rm -rf dist/
    python -m build

publish-test:
    twine upload --repository testpypi dist/*

publish:
    twine upload dist/*

