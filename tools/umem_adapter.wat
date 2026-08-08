(module
  (import "env" "memory" (memory $umem 1 65536))
  (func (export "load8") (param i32) (result i32) local.get 0 i32.load8_u)
  (func (export "load64") (param i32) (result i64) local.get 0 i64.load)
  (func (export "store8") (param i32 i32) local.get 0 local.get 1 i32.store8)
  (func (export "store64") (param i32 i64) local.get 0 local.get 1 i64.store)
)
