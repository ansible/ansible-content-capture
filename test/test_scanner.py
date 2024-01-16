from ansible_scan_core.scanner import AnsibleScanner


scanner = AnsibleScanner()


def test_scan_yaml():
    target_yaml = """
---
- hosts: localhost
  tasks:
    - name: sample task
      debug:
        msg: "Hello, World!"
"""
    scanner.evaluate(type="playbook", raw_yaml=target_yaml)
    scandata = scanner.get_last_scandata()
    print(scandata)