<script>
    import Card from "$lib/components/Card.svelte";
    import writeups from "../../data/writeups";
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
    .cards {   
        list-style: none;
    }
</style>

<body>
    <div id="summary">
        <p>
            I frequently play CTFs with my team <a href = "https://ctftime.org/team/186494">Psi Beta Rho</a>, which is the competitive team at UCLA. We ended the 2023 year 8th in the United States and top 100 in the world. I specialize in cryptography but also try to mess around with anything I can. For writeups that I have done, just look below!
        </p>
    </div>
    <div>
        <h1>
            Write ups
        </h1>
    </div>
    <ul id="writeups">
            {#each writeups as write}
            <li class="cards">
                <Card title={write['title']} discription={write['discription']} link={write['link']} CTF={write['ctf']}/>
            
            </li>
                
            {/each}
        

    </ul>
</body>