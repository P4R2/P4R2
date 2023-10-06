# P4R2
P4R2 is a P4 runtime reconfiguration mechanism that make it possible for operators only compile P4 code and run switch once and later (re)configure all kinds of switch tasks at runtime.

### Features

* An example implementation of P4R2 data plane
* P4R2 control plane cmd controller
* Example of P4R2 primitives and the swtich tasks composed by them
* P4R2 code generator

### Running P4R2

##### Requirement

* A tofino-based hardware switch or vitural environment with Python2,3 and bf-SDE 9.4.0+

##### Running Data Plane 

Note:  the first two steps can be skipped because there is already code which can be run under the directory $P4R2_PATH/p4src

* Edit the initial configuration and generate custom data plane code (Python Jinja2 module needed)

  ```bash
  vim $P4R2_PATH/config.json
  python $P4R2_PATH/P4R2compiler.py
  ```

* Add custom headers and their parsing logic in ./p4src/headers.p4 and  ./p4src/parsers.p4 and customize the KS and HM operation set in ./p4src/p4r2.p4

* Compile and run data plane

  ```bash
  ./$SDE/p4_build.sh $P4R2_PATH/p4src/p4r2.p4
  ./$SDE/run_switchd.sh -p p4r2
  ```

##### Running Control Plane

* ```bash
  .$P4R2_PATH/control_plane/run.sh
  ```

  If no error occurs:

  ```bash
  Subscribe attempt #1
  Subscribe response received 0
  Binding with p4_name p4r2
  Binding with p4_name p4r2 successful!!
  Received p4r2 on GetForwarding on client 0, device 0
  connect successfully!
  p4 program: p4r2
  client id: 0
  
  
  
      P4R2 controller start!!
      
  P4R2> 
  ```

##### Deploying swith tasks

* Using the example primitives to deploy tasks

  ```bash
  P4R2> parse_primitive --help
  usage: p4r2_main.py [-h] -f FILE -p P
  
  optional arguments:
    -h, --help            show this help message and exit
    -f FILE, --file FILE  e.g., ./primitives.txt
    -p P, --print P       0 or 1, 0 means no detail is printed, 1 is the
                          opposite
  ```

  ```bash
  P4R2> parse_primitive -p 0 -f ../example_primitives/cms.txt
  
  primitive parsing success
  parsing time:   3.13305854797ms
  dumping time:   12.4650001526ms
  total time:     15.5980587006ms
  ```

* Clear all existing entries

  ```bash
  P4R2> clear_all
  ```
