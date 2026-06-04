"""
ne_xref.py - Cross-Reference and Call Graph Builder for NE Executables

Builds a call graph from NE relocation data, showing which code segments call
which other segments, finds connected-component clusters of code, reports
imported-function usage per segment, and emits a DOT graph for visualization.

Usage:
    python ne_xref.py <ne_exe> [--graph] [--clusters] [--imports] [--dot]
"""

import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))

from ne_parse import parse_ne, NEHeader


def build_call_graph(ne: NEHeader) -> dict:
    """Build segment-level call graph from relocations.
    Returns dict: source_seg -> set of (target_seg, target_off, reloc_type, count)
    """
    graph = defaultdict(lambda: defaultdict(int))  # src_seg -> target_seg -> count

    for seg in ne.segments:
        if not seg.is_code:
            continue
        for r in seg.relocations:
            target_type = r.flags & 3
            if target_type == 0:  # Internal reference
                if r.target_seg > 0 and r.target_seg != 0xFF:
                    target = ne.segments[r.target_seg - 1]
                    if target.is_code:
                        graph[seg.index][r.target_seg] += 1

    return dict(graph)


def build_data_refs(ne: NEHeader) -> dict:
    """Build code->data segment reference map."""
    refs = defaultdict(set)
    for seg in ne.segments:
        if not seg.is_code:
            continue
        for r in seg.relocations:
            target_type = r.flags & 3
            if target_type == 0 and r.target_seg > 0 and r.target_seg != 0xFF:
                target = ne.segments[r.target_seg - 1]
                if target.is_data:
                    refs[seg.index].add(r.target_seg)
    return dict(refs)


def find_clusters(graph: dict, ne: NEHeader) -> list:
    """Find clusters of tightly-coupled code segments using connected components."""
    # Build undirected adjacency
    adj = defaultdict(set)
    for src, targets in graph.items():
        for tgt in targets:
            adj[src].add(tgt)
            adj[tgt].add(src)

    visited = set()
    clusters = []

    for seg in ne.code_segments:
        if seg.index in visited:
            continue
        # BFS
        cluster = set()
        queue = [seg.index]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            cluster.add(node)
            for neighbor in adj.get(node, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        if cluster:
            clusters.append(sorted(cluster))

    # Sort clusters by size (largest first)
    clusters.sort(key=len, reverse=True)
    return clusters


def print_call_graph(ne: NEHeader):
    """Print the segment-level call graph."""
    graph = build_call_graph(ne)
    data_refs = build_data_refs(ne)

    print(f"=== Call Graph for {ne.filename} ===")
    print(f"Code segments with outgoing calls: {len(graph)}")
    print()

    for src in sorted(graph.keys()):
        seg = ne.segments[src - 1]
        targets = graph[src]
        data = data_refs.get(src, set())
        code_targets = sorted(targets.keys())
        print(f"Seg {src:3d} ({seg.actual_size:5d}B) -> code: {code_targets}")
        if data:
            print(f"{'':>22s} -> data: {sorted(data)}")


def print_clusters(ne: NEHeader):
    """Print connected component clusters."""
    graph = build_call_graph(ne)
    clusters = find_clusters(graph, ne)

    print(f"=== Code Segment Clusters for {ne.filename} ===")
    print(f"Total clusters: {len(clusters)}")
    print()

    for i, cluster in enumerate(clusters):
        total_size = sum(ne.segments[s-1].actual_size for s in cluster
                         if s <= len(ne.segments))
        print(f"Cluster {i+1}: {len(cluster)} segments, {total_size:,} bytes")
        # Show segments with their sizes
        segs_info = []
        for s in cluster:
            seg = ne.segments[s-1]
            segs_info.append(f"{s}({seg.actual_size})")
        # Print in rows of 10
        for j in range(0, len(segs_info), 10):
            print(f"  {', '.join(segs_info[j:j+10])}")
        print()


def _import_name(ne: NEHeader, r) -> str:
    """Human-readable name for an import relocation, using only the binary's
    own tables. Import-by-ordinal -> MODULE.<ordinal>; import-by-name ->
    MODULE.<name> resolved through the import name table."""
    mod = (ne.module_names[r.module_idx - 1]
           if 1 <= r.module_idx <= len(ne.module_names) else f"mod{r.module_idx}")
    target_type = r.flags & 3
    if target_type == 2:  # import by name: r.ordinal is an import-name-table offset
        try:
            import_base = ne.ne_offset + struct_unpack_import_off(ne)
        except Exception:
            import_base = None
        if import_base is not None:
            off = import_base + r.ordinal
            data = ne.raw_data
            if 0 <= off < len(data):
                n = data[off]
                name = data[off + 1:off + 1 + n].decode('ascii', errors='replace')
                return f"{mod}.{name}"
        return f"{mod}.@{r.ordinal}"
    return f"{mod}.{r.ordinal}"


def struct_unpack_import_off(ne: NEHeader) -> int:
    """Re-read the import-name-table offset from the NE header (field at +42)."""
    import struct
    return struct.unpack_from('<H', ne.raw_data, ne.ne_offset + 42)[0]


def print_import_usage(ne: NEHeader):
    """Print imported-function usage per code segment.

    Driven entirely by the binary's module-reference and import-name tables --
    no per-application ordinal database required. For a project that has built
    a runtime-library ordinal map (e.g. a DOS extender's import library), wrap
    this and substitute friendly names for the relevant module index."""
    print(f"=== Imported Function Usage by Segment ===")
    if ne.module_names:
        print(f"Modules: {', '.join(f'{i+1}:{m}' for i, m in enumerate(ne.module_names))}")
    print(f"{'Seg':>4s} {'Size':>6s}  imports called (count)")
    print("-" * 60)

    for seg in ne.code_segments:
        calls = defaultdict(int)
        for r in seg.relocations:
            if (r.flags & 3) in (1, 2):  # import by ordinal or by name
                calls[_import_name(ne, r)] += 1

        if calls:
            calls_str = ', '.join(f'{name}({count})' for name, count in
                                  sorted(calls.items()))
            print(f"{seg.index:4d} {seg.actual_size:6d}  {calls_str}")


def print_dot_graph(ne: NEHeader):
    """Print DOT format graph for visualization."""
    graph = build_call_graph(ne)

    print("digraph ne_callgraph {")
    print("  rankdir=LR;")
    print("  node [shape=box, fontsize=10];")

    for seg in ne.code_segments:
        size = seg.actual_size
        # Color by size
        if size > 10000:
            color = "#ff6666"
        elif size > 3000:
            color = "#ffaa66"
        elif size > 1000:
            color = "#ffff66"
        else:
            color = "#aaffaa"
        print(f'  seg{seg.index} [label="Seg {seg.index}\\n{size}B", '
              f'style=filled, fillcolor="{color}"];')

    for src, targets in graph.items():
        for tgt, count in targets.items():
            width = min(3.0, 0.5 + count * 0.1)
            print(f'  seg{src} -> seg{tgt} [penwidth={width:.1f}];')

    print("}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ne_exe> [--graph] [--clusters] [--imports] [--dot]")
        sys.exit(1)

    ne = parse_ne(sys.argv[1])

    if '--dot' in sys.argv:
        print_dot_graph(ne)
    elif '--clusters' in sys.argv:
        print_clusters(ne)
    elif '--imports' in sys.argv:
        print_import_usage(ne)
    else:
        print_call_graph(ne)


if __name__ == '__main__':
    main()
