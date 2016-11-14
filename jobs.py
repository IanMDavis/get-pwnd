"""
The Jobs module solves the problem of running different access modules in parallel.
"""

import multiprocessing

class Dispatcher:
    """
    Dispatcher runs added access modules against discovered services in parallel.
    """

    # E.g.: {'ssh': test_ssh_function}
    modules_dict = {}

    def add_tester(self, service, test_access_func):
        """
        This function must be called right after the Dispatcher is instantiated.

        Args:
            service (string): The name of the service, e.g. 'ssh'.
            test_access_func (func): description
                The function to test access. Must have this signature:
                test_access_func(ip, port, credentials) -> (login, password) | None

        Raises:
            Exception: If module for this service already exist.
        """
        if service in self.modules_dict:
            raise Exception("Access module for service %s is already declared" % (service))
        self.modules_dict[service] = test_access_func

    def run(self, services_by_ip, credentials):
        """
        Runs added modules in several threads.

        Args:
            services_by_ip (dict): description
                Services to be tested for access. Must be in the following format:
                {'192.168.1.1': {'ssh': 22, 'telnet': 23}}
            credentials (dict): login -> passwords pairs to test against.

        Returns:
            Dictionary containing successful results in the following format:
            {'192.168.1.1': {'ssh': (22, 'login', 'password')}}
        """
        cpus = multiprocessing.cpu_count()
        pool = multiprocessing.Pool(processes=cpus)
        results = []
        for ip in services_by_ip:
            services_dict = services_by_ip[ip]
            for service in services_dict:
                if service in self.modules_dict:
                    tester_func = self.modules_dict[service]
                    port = services_dict[service]
                    res = pool.apply_async(tester_func, (ip, port, credentials))
                    results.append({
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "res": res,
                        })

        # Gather results.
        successful = {}
        for res in results:
            login_results = res["res"].get(timeout=30)
            if login_results is None:
                continue
            ip = res["ip"]
            if ip not in successful:
                successful[ip] = {}
            for entry in login_results:
                try:
                    successful[ip][res["service"]].append((res["port"], entry[0], entry[1]))
                except KeyError:
                    successful[ip][res["service"]] = [(res["port"], entry[0], entry[1])]
        return successful
