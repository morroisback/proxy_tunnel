import re

from proxy_tunnel import ProxyTunnel, Proxy


def parse_proxy_ports_file(proxies_file_path: str) -> list[Proxy]:
    with open(proxies_file_path, "r") as file:
        lines = list(map(lambda line: line.strip(), file.readlines()))

    proxies = []
    for proxy_line in lines:
        host = re.findall(r"@(.*?):", proxy_line)[0]
        port = re.findall(r"@.*?:(.*?):", proxy_line)[0]
        username = re.findall(r"http:\/\/(.*?):", proxy_line)[0]
        password = re.findall(r".*:(.*)@", proxy_line)[0]
        refresh_url = re.findall(r"\[(.*?)\]", proxy_line)[0]
        proxies.append(Proxy(host, port, username, password, refresh_url))
    return proxies


def main() -> None:
    local_proxy = Proxy("127.0.0.1", "12345")

    proxies = parse_proxy_ports_file(".env/proxies.txt")
    remote_proxy = proxies[0]

    tunnel = ProxyTunnel(local_proxy, remote_proxy)
    tunnel.start()


if __name__ == "__main__":
    main()
