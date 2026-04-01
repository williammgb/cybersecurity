from simulation import CyberNetworkSimulation, SimulationConfig

def main() -> None:
    cfg = SimulationConfig(
        initial_nodes=15,
        initial_edges=25,
        suspicious_threshold=3,
        prob_add_node=0.1,
        prob_add_edge=0.15,
        prob_send_message=0.4,
    )
    sim = CyberNetworkSimulation(network_name="DemoNet", config=cfg)
    sim.run(steps=400)
    print(sim.summary())
    print()
    for name in sorted(sim.network.nodes.keys())[:5]:
        intel = sim.neighbor_intel(name)
        if intel:
            print(f"--- {intel.node_name} ---")
            print(f"  criminal: {intel.is_criminal}, suspicious_msgs: {intel.suspicious_count}, sent: {intel.total_messages_sent}")
            print(f"  closest friends: {intel.closest_friends[:5]}")
            print(f"  flagged neighbors: {intel.neighbors_flagged}")
            print()


if __name__ == "__main__":
    main()
