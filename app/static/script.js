function showGraph(graphId) {
    const graphs = document.querySelectorAll('.container');
    graphs.forEach(graph => graph.style.display = 'none');

    const selectedGraph = document.getElementById(graphId);
    if (selectedGraph) {
        selectedGraph.style.display = 'flex';
    }
}