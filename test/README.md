## Test for HugeTLB pages translation

#### 1. Prepare hugepages

```
$ sudo sysctl vm.nr_hugepages=100
```

#### 2. Write pattern to the hugepage

```
$ sudo ./hugetlb_test 0xdeadbeef
pid = 12953, virt = 0x2aaaaac00000, phys = 0x1fbd600000
pid = 12953, virt = 0x2aaaaac01008, phys = 0x1fbd601008
```

#### 3. Check written data from /dev/crash

```
sudo ./read_dev_crash.py 0x1fbd600000 `python -c "print(2*1024*1024)"`
```

## Test for `VM_PFNMAP` pages translation

#### 1. Load VE driver

```
$ sudo modprobe ve_drv
```

#### 2. Execute test program
```
$ sudo ./pfnmap_test

```
