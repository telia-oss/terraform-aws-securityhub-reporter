## Securityhub reporter lambda


This module creates a lambda that will read status of selected controls in Security Hub's `AWS Foundational Security Best Practices v1.0.0` and reports the results to the selected Slack channel and custom Cloudwatch metric.

### Unit testing

For running unit tests run command (in project root):
```python
python3 tests/test_security_hub_reporter.py
```