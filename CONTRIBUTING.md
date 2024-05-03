# Contributing

## RefCell debugging

To debug RefCell, use:

```sh
cargo +nightly r -Zbuild-std -Zbuild-std-features=core/debug_refcell --target <target>
```

where target is `host: <target>`:

```sh
rustc -vV
```
