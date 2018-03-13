wolrs
====

[![Build Status](https://travis-ci.org/linde12/wolrs.svg?branch=master)](https://travis-ci.org/linde12/wolrs)

A Rust library for constructing WakeOnLAN packets.

## Example

To create a new packet:

```rust
extern crate wolrs;
use wolrs::create_magic_packet;

fn main() {
  let packet = create_magic_packet("01:02:03:0A:0B:0F");
  println!("{:?}", &packet[..]);
}
```
