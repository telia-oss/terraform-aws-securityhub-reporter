### How to run the test ?

Go to the root directory containing src and test directories and run:

```commandline
python3 -m tests.test_security_hub_reporter
```

    
In order to run the lambda function against AWS account:
- set AWS credentials in bash
- put correct values to lambda_env_template.py and run

  ``` commandline
  python3 -m tests.test_run_locally
  ```  

There is possible to run the test directly from your IDE, just go to the py file and run.