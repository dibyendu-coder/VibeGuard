# CI Workflow Fixture

## Expected Detections
- VBG-DEP-006: Echoing secrets into CI logs (`echo ${{ secrets.AWS_SECRET_ACCESS_KEY }}`)
- VBG-DEP-007: Unpinned third-party action (`actions/checkout@v2`)

## Should NOT Detect
- Code-level SQL injections
