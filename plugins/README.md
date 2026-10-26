# Adapter plugins

PhantomX supports explicit in-process adapter registration. A plugin implements
the `PluginAdapter` protocol in `plugins/base.py` and is registered by trusted
application setup code:

```python
manager = AdapterManager()
manager.register("custom-scanner", CustomScannerAdapter())
```

`scan(tool, target, executor, extra_args=None)` receives the complete registered
tool configuration. Use the supplied executor for process execution so configured
arguments, timeouts, bounded retries, output decoding, and `shell=False` behavior
remain in effect. Return a `ToolResult` with a meaningful status and preserve
stdout/stderr when parsing fails.

Plugins are not auto-imported from directories or discovered from the environment.
This avoids executing arbitrary files from an untrusted plugin path. The CLI's
`tools add` command can also register a tool without a specialized adapter; it
uses the shared generic executor.
