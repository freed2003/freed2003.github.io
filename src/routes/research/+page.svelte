<script>
    import publications from "../../data/publications.js"
    import Pub from "$lib/components/Pub.svelte"
</script>

<style>
    body {
        width: 100%;
        display: flex;
        justify-content: center;
        align-items: center;
        flex-direction: column;
    }
    #summary {
        /* position: absolute;
        left: 25%; */
        text-align: center;
        width: 50%;
    }
    #summary > p{
        text-align: center;
        
        font-size: 20px;
    }
    a {
        color: gray;
    }

    
</style>

<body>
    <div id="summary">
        <p>
            Research topics I am interested in include computer security and cryptography. I am currently working with the SyssArch lab at UCLA and will be doing security research in Albuquerque with Sandia National Lab in the summer. For a list of publications I have worked on, please see below, or my <a href="https://scholar.google.com/citations?user=eg77CLEAAAAJ&hl=en">google scholar</a>.
        </p>
    </div>
    <div>
        <h1>
            Publications
        </h1>
    </div>
    <ul>
        {#each publications as entry}
        <li>
            <Pub title = {entry["title"]} authors = {entry["authors"]} year = {entry["year"]} place = {entry["place"]} link={entry["link"]}/>
        </li>
        
        {/each}
    </ul>
    
</body>