..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

Eventdev CPU Loopback Sample Application
===========================================

The eventdev_cpu_loopback example is a simple event pipeline application that
uses CPU-generated traffic to test the IHQM PMD.

Compiling the Application
-------------------------

To compile the application:

#.  Go to the sample application directory:

    .. code-block:: console

        export RTE_SDK=/path/to/rte_sdk
        cd ${RTE_SDK}/examples/eventdev_cpu_loopback

#.  Set the target (a default target is used if not specified). For example:

    .. code-block:: console

        export RTE_TARGET=x86_64-native-linuxapp-gcc

    See the *DPDK Getting Started Guide* for possible RTE_TARGET values.

#.  Build the application:

    .. code-block:: console

        make

Running the Application
-----------------------

The application consists of an event producer, one or more worker threads, and
an event consumer.

The event producer continuously enqueues events to a load-balanced queue via its
directed port. These events can be subjected to atomic, ordered, or unordered
scheduling. The workers continuously dequeue and forward these events to a
directed queue, from which the event consumer continuously dequeues. The
producer, workers, and consumer all run in separate threads.

Before running the application, the HQM kernel driver must be loaded:

.. code-block:: console

    insmod /path/to/hqm.ko

An example invocation of eventdev_cpu_loopback using these settings is shown
below:

 * ``-w 1``: Number of worker threads
 * ``-q``: Minimize printed output
 * ``-n 64``: Send 64 packets

.. code-block:: console

    ./build/eventdev_cpu_loopback --vdev event_ihqm,dir_port_ids=0:1,dir_queue_ids=0:1 -- -w 1 -q -n 64

Note that since the producer and consumer threads use directed ports, those
must be specified in the vdev arguments. See the IHQM Event Device Driver guide
for more details on its supported vdev arguments.

Expected Output:

.. code-block:: console

  Consumer done! RX=[-n argument]
  Producer thread done! TX=[-n argument] across [-f argument, default 16] flows


Running the Application (DM)
----------------------------

The application also supports a simple DM test with the '-D' argument. The DM
test uses two eventdevs, one for the producer and one for the consumer, and
each uses one load-balanced port. The producer enqueues (via DM) to an event
queue in the consumer's eventdev, to which the consumer port is connected.

The test is single-threaded and does one event at a time: send one event, wait
to receive it, then repeat.

To run the DM test:

.. code-block:: console

    ./build/eventdev_cpu_loopback --vdev="event_ihqm,dm_enabled=true,domain_name=dm0" --vdev="event_ihqm1,dm_enabled=true,domain_name=dm1" -- -w 1 -q -n 100 -D
