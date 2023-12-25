<script>

</script>

<style>
    #gary {
        width: 350px;
        height: auto;
        margin: auto;
        border-radius: 25px;
        border: 10px solid black;
    }
    .main {
        display: flex;
        justify-content: center;    
    }
    .large {
        padding: 7rem;
        width: 80%;
        display: flex;
        justify-content: space-evenly;
        align-items: center;
    }
    .left {
        display: inline;
        margin: 3rem;
        padding: 0px;


    }
    .right {
        display: inline;
        margin: 3rem;
        width: 40%;
        font-size: 25px;
    }
    .right > div {
        display: flex;
        align-items: center;
    }
    span {
        margin-right: 1rem;
    }
</style>

<main>
    <body class="main">
        <div class="large">
            <div class ="left">
                <img src="src/images/gary.jpg" alt="meeee" id="gary"/>
            </div>
            <div class ="right">
                <p>
                    Hi! My name is Gary and I am a 3rd year student at UCLA studying computer science and mathematics. If you want to see more about what I do with my time feel free to click any of the links above!
                </p>
                <div>
                    <span>
                        Contact: 
                    </span>
                    <span>
                        <a href="mailto:gary.song2003@gmail.com">
                            <img src="src/images/email.png" style= "width:35px; height: auto" alt="email"/>
                        </a>
                    </span>
                    <span>
                        <a href="https://github.com/freed2003">
                            <img src="src/images/github.png" style= "width: 30px; height: auto" alt="email"/>
                        </a>
                    </span>
                </div>
            </div>
        </div>
    </body>
</main>