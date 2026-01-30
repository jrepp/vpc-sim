<script>
  import { onMount } from "svelte";
  import * as d3 from "d3";

  const API_BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");

  let state = {
    vpcs: [],
    subnets: [],
    route_tables: [],
    internet_gateways: [],
    vpc_peerings: [],
    dhcp_options: [],
    security_groups: []
  };
  let loading = true;
  let error = "";
  let sourceSubnetId = "";
  let destinationCidr = "0.0.0.0/0";
  let validation = null;
  let tfProfiles = [];
  let tfProfile = "";
  let tfRunning = false;
  let tfError = "";
  let tfRun = null;
  let activeTab = "data";
  let graphContainer;

  async function loadState() {
    loading = true;
    error = "";
    try {
      const res = await fetch(`${API_BASE}/state`);
      if (!res.ok) throw new Error(`State load failed: ${res.status}`);
      state = await res.json();
    } catch (err) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  async function runValidation() {
    validation = null;
    error = "";
    if (!sourceSubnetId || !destinationCidr) {
      error = "Select a subnet and destination CIDR";
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/validate/connectivity`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_subnet_id: sourceSubnetId,
          destination_cidr: destinationCidr
        })
      });
      if (!res.ok) throw new Error(`Validation failed: ${res.status}`);
      validation = await res.json();
    } catch (err) {
      error = err.message;
    }
  }

  async function loadProfiles() {
    tfError = "";
    try {
      const res = await fetch(`${API_BASE}/terraform/profiles`);
      if (!res.ok) throw new Error(`Terraform profiles load failed: ${res.status}`);
      const data = await res.json();
      tfProfiles = data.profiles || [];
      if (!tfProfile && tfProfiles.length) {
        tfProfile = tfProfiles[0];
      }
    } catch (err) {
      tfError = err.message;
    }
  }

  async function runTerraform(step) {
    if (!tfProfile) {
      tfError = "Select a Terraform profile";
      return;
    }
    tfRunning = true;
    tfError = "";
    tfRun = null;
    try {
      const res = await fetch(`${API_BASE}/terraform/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile: tfProfile, step })
      });
      if (!res.ok) {
        const message = await res.text();
        throw new Error(message || `Terraform run failed: ${res.status}`);
      }
      tfRun = await res.json();
    } catch (err) {
      tfError = err.message;
    } finally {
      tfRunning = false;
    }
  }

  function buildGraphData() {
    const nodes = [];
    const links = [];

    state.vpcs.forEach((vpc) => {
      nodes.push({ id: vpc.id, label: vpc.id, type: "vpc" });
    });
    state.subnets.forEach((subnet) => {
      nodes.push({ id: subnet.id, label: subnet.id, type: "subnet" });
      links.push({
        source: subnet.vpc_id,
        target: subnet.id,
        label: "subnet"
      });
      if (subnet.route_table_id) {
        links.push({
          source: subnet.route_table_id,
          target: subnet.id,
          label: "assoc"
        });
      }
    });
    state.route_tables.forEach((table) => {
      nodes.push({ id: table.id, label: table.id, type: "route-table" });
      links.push({
        source: table.vpc_id,
        target: table.id,
        label: "route-table"
      });
      table.routes.forEach((route) => {
        const linkTarget = route.target_id;
        links.push({
          source: table.id,
          target: linkTarget,
          label: route.destination_cidr
        });
      });
    });
    state.internet_gateways.forEach((igw) => {
      nodes.push({ id: igw.id, label: igw.id, type: "igw" });
      if (igw.vpc_id) {
        links.push({
          source: igw.vpc_id,
          target: igw.id,
          label: "igw"
        });
      }
    });

    state.vpc_peerings.forEach((peering) => {
      links.push({
        source: peering.requester_vpc_id,
        target: peering.accepter_vpc_id,
        label: "peer"
      });
    });

    const nodeIds = new Set(nodes.map((n) => n.id));
    const filteredLinks = links.filter(
      (link) => nodeIds.has(link.source) && nodeIds.has(link.target)
    );

    return { nodes, links: filteredLinks };
  }

  function renderGraph() {
    if (!graphContainer) return;
    graphContainer.innerHTML = "";

    const { nodes, links } = buildGraphData();
    if (!nodes.length) {
      graphContainer.innerHTML = "<p class='muted'>No resources to visualize.</p>";
      return;
    }

    const width = graphContainer.clientWidth || 800;
    const height = 520;

    const svg = d3
      .select(graphContainer)
      .append("svg")
      .attr("width", width)
      .attr("height", height);

    const link = svg
      .append("g")
      .attr("class", "graph-links")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("class", "link");

    const linkLabel = svg
      .append("g")
      .attr("class", "graph-link-labels")
      .selectAll("text")
      .data(links)
      .join("text")
      .attr("class", "link-label")
      .text((d) => d.label);

    const node = svg
      .append("g")
      .attr("class", "graph-nodes")
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", 18)
      .attr("class", (d) => `node ${d.type}`);

    const nodeLabel = svg
      .append("g")
      .attr("class", "graph-node-labels")
      .selectAll("text")
      .data(nodes)
      .join("text")
      .attr("class", "node-label")
      .text((d) => d.label);

    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance(90))
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide(32));

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      linkLabel
        .attr("x", (d) => (d.source.x + d.target.x) / 2)
        .attr("y", (d) => (d.source.y + d.target.y) / 2);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);

      nodeLabel
        .attr("x", (d) => d.x)
        .attr("y", (d) => d.y + 32);
    });
  }

  onMount(() => {
    loadState();
    loadProfiles();
  });

  $: if (activeTab === "graph") {
    state.vpcs;
    state.subnets;
    state.route_tables;
    state.internet_gateways;
    renderGraph();
  }
</script>

<main>
  <header class="hero">
    <div>
      <p class="eyebrow">VPC Simulation</p>
      <h1>Local VPC model with Terraform-driven state</h1>
      <p class="lede">
        Use the AWS provider against this endpoint to validate routing intent before you
        touch real infrastructure.
      </p>
    </div>
    <div class="hero-actions">
      <button class="ghost" on:click={loadState}>Refresh state</button>
      <span class="status">{loading ? "Syncing" : "Ready"}</span>
    </div>
  </header>

  {#if error}
    <div class="alert">{error}</div>
  {/if}

  <section class="tabs">
    <button
      class:active={activeTab === "data"}
      on:click={() => (activeTab = "data")}
    >
      Data view
    </button>
    <button
      class:active={activeTab === "graph"}
      on:click={() => (activeTab = "graph")}
    >
      Graph view
    </button>
  </section>

  {#if activeTab === "data"}
    <section class="grid">
      <article class="card">
        <h2>VPCs</h2>
        {#if state.vpcs.length === 0}
          <p class="muted">No VPCs yet.</p>
        {:else}
          <ul>
            {#each state.vpcs as vpc}
              <li>
                <span class="mono">{vpc.id}</span>
                <span>{vpc.cidr_block}</span>
                {#if vpc.ipv6_cidr_block}
                  <span class="muted">{vpc.ipv6_cidr_block}</span>
                {/if}
                {#if vpc.dhcp_options_id}
                  <span class="muted">dhcp: {vpc.dhcp_options_id}</span>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </article>

      <article class="card">
        <h2>Subnets</h2>
        {#if state.subnets.length === 0}
          <p class="muted">No subnets yet.</p>
        {:else}
          <ul>
            {#each state.subnets as subnet}
              <li>
                <span class="mono">{subnet.id}</span>
                <span>{subnet.cidr_block}</span>
                {#if subnet.ipv6_cidr_block}
                  <span class="muted">{subnet.ipv6_cidr_block}</span>
                {/if}
                <span class="muted">{subnet.route_table_id || "no route table"}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </article>

      <article class="card">
        <h2>Route Tables</h2>
        {#if state.route_tables.length === 0}
          <p class="muted">No route tables yet.</p>
        {:else}
          <ul>
            {#each state.route_tables as table}
              <li>
                <span class="mono">{table.id}</span>
                <span>{table.vpc_id}</span>
                <span class="muted">{table.routes.length} routes</span>
              </li>
            {/each}
          </ul>
        {/if}
      </article>

    <article class="card">
      <h2>Internet Gateways</h2>
        {#if state.internet_gateways.length === 0}
          <p class="muted">No internet gateways yet.</p>
        {:else}
          <ul>
            {#each state.internet_gateways as igw}
              <li>
                <span class="mono">{igw.id}</span>
                <span>{igw.vpc_id || "detached"}</span>
              </li>
            {/each}
          </ul>
        {/if}
    </article>

    <article class="card">
      <h2>VPC Peerings</h2>
      {#if state.vpc_peerings.length === 0}
        <p class="muted">No peering connections yet.</p>
      {:else}
        <ul>
          {#each state.vpc_peerings as peering}
            <li>
              <span class="mono">{peering.id}</span>
              <span>{peering.requester_vpc_id} ↔ {peering.accepter_vpc_id}</span>
              <span class="muted">{peering.status}</span>
            </li>
          {/each}
        </ul>
      {/if}
    </article>

    <article class="card">
      <h2>Security Groups</h2>
      {#if state.security_groups.length === 0}
        <p class="muted">No security groups yet.</p>
      {:else}
        <ul>
          {#each state.security_groups as group}
            <li>
              <span class="mono">{group.id}</span>
              <span>{group.name}</span>
              <span class="muted">{group.rules.length} rules</span>
            </li>
          {/each}
        </ul>
      {/if}
    </article>

    <article class="card">
      <h2>DHCP Options</h2>
      {#if state.dhcp_options.length === 0}
        <p class="muted">No DHCP options yet.</p>
      {:else}
        <ul>
          {#each state.dhcp_options as options}
            <li>
              <span class="mono">{options.id}</span>
            </li>
          {/each}
        </ul>
      {/if}
    </article>
    </section>
  {:else}
    <section class="card wide graph-card">
      <div class="card-header">
        <h2>Network Graph</h2>
        <p class="muted">Connections between VPCs, subnets, route tables, and IGWs.</p>
      </div>
      <div class="graph-container" bind:this={graphContainer}></div>
      <div class="graph-legend">
        <span class="legend-item vpc">VPC</span>
        <span class="legend-item subnet">Subnet</span>
        <span class="legend-item route">Route table</span>
        <span class="legend-item igw">IGW</span>
      </div>
    </section>
  {/if}

  <section class="card wide">
    <div class="card-header">
      <h2>Connectivity Validation</h2>
      <p class="muted">Pick a subnet and destination to test the active route.</p>
    </div>
    <div class="form">
      <label>
        Source subnet
        <select bind:value={sourceSubnetId}>
          <option value="">Select a subnet</option>
          {#each state.subnets as subnet}
            <option value={subnet.id}>{subnet.id} · {subnet.cidr_block}</option>
          {/each}
        </select>
      </label>
      <label>
        Destination CIDR
        <input type="text" bind:value={destinationCidr} placeholder="0.0.0.0/0" />
      </label>
      <button class="small" on:click={runValidation}>Validate</button>
    </div>

    {#if validation}
      <div class="validation">
        <div>
          <h3>{validation.reachable ? "Reachable" : "Blocked"}</h3>
          <p class="muted">Matched route: {validation.matched_route?.destination_cidr || "none"}</p>
        </div>
        <div class="validation-meta">
          <p class="mono">Route table: {validation.route_table_id || "none"}</p>
          {#if validation.warnings.length}
            <ul>
              {#each validation.warnings as warn}
                <li>{warn}</li>
              {/each}
            </ul>
          {/if}
        </div>
      </div>
    {/if}
  </section>

  <section class="card wide">
    <div class="card-header">
      <h2>Terraform Runner</h2>
      <p class="muted">Run init, plan, and apply against the current simulator state.</p>
    </div>
    {#if tfError}
      <div class="alert">{tfError}</div>
    {/if}
    <div class="form">
      <label>
        Profile
        <select bind:value={tfProfile}>
          {#if tfProfiles.length === 0}
            <option value="">No profiles found</option>
          {:else}
            {#each tfProfiles as profile}
              <option value={profile}>{profile}</option>
            {/each}
          {/if}
        </select>
      </label>
      <label>
        Actions
        <div class="actions">
          <button disabled={tfRunning} on:click={() => runTerraform("init")}>Init</button>
          <button disabled={tfRunning} on:click={() => runTerraform("plan")}>Plan</button>
          <button disabled={tfRunning} on:click={() => runTerraform("apply")}>Apply</button>
          <button class="ghost" disabled={tfRunning} on:click={() => runTerraform("all")}>
            Run all
          </button>
        </div>
      </label>
    </div>

    {#if tfRunning}
      <p class="muted">Terraform running…</p>
    {/if}

    {#if tfRun}
      <div class="terraform-output">
        <div class="terraform-meta">
          <span class="mono">profile: {tfRun.profile}</span>
          <span>{tfRun.success ? "success" : "failed"}</span>
        </div>
        {#each tfRun.steps as step}
          <div class="terraform-step">
            <h3>{step.step} · exit {step.exit_code}</h3>
            <pre>{step.output}</pre>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</main>
