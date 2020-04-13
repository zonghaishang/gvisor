load("//tools:defs.bzl", "go_binary")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_binary(
    name = "main",
    testonly = 1,
    srcs = ["main.go"],
    deps = ["//runsc/dockerutil"],
)
