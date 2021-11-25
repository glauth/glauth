Vendored libraries. Not to be mistaken for libraries included under `vendor/` which is a go convention.

To upgrade toml:

1. clone from upstream
2. add to `decode_meta.go`:

```
func (md *MetaData) Mappings() map[string]interface{} {
  return md.mapping
}
```
3. Run `gofmt -w ./` in `vendored/`
