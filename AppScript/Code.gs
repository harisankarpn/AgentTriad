/**
 * Automatically creates the custom menu in Google Docs.
 */
function onOpen() {
  DocumentApp.getUi()
    .createMenu('⚡ Agent Triad')
    .addItem('🚀 Open GCP Workflow Visualizer', 'openVisualizerModal')
    .addToUi();
}

/**
 * Opens the visualizer in optimized modal dimensions.
 */
function openVisualizerModal() {
  const html = HtmlService.createHtmlOutputFromFile('Visualizer')
    .setWidth(1150)
    .setHeight(720)
    .setTitle('GCP Support Architecture: Current vs. Agent Triad');
  DocumentApp.getUi().showModalDialog(html, 'GCP Support Architecture');
}
