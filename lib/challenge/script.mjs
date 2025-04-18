import {setup, challenge} from "{{ .ChallengeScript }}";


// from Xeact
const u = (url = "", params = {}) => {
    let result = new URL(url, window.location.href);
    Object.entries(params).forEach((kv) => {
        let [k, v] = kv;
        result.searchParams.set(k, v);
    });
    return result.toString();
};

(async () => {
    const status = document.getElementById('status');
    const title = document.getElementById('title');
    const spinner = document.getElementById('spinner');

    status.innerText = 'Starting challenge {{ .Challenge }}...';

    try {
        const info = await setup({
            Path: "{{ .Path }}",
            Parameters: "{{ .Parameters }}"
        });

        if (info != "") {
            status.innerText = 'Calculating... ' + info
        } else {
            status.innerText = 'Calculating...';
        }
    } catch (err) {
        title.innerHTML = "Oh no!";
        status.innerHTML = `Failed to initialize: ${err.message}`;
        spinner.innerHTML = "";
        spinner.style.display = "none";
        return
    }


    try {
        const t0 = Date.now();
        const { result, info } = await challenge();
        const t1 = Date.now();
        console.log({ result, info });

        title.innerHTML = "Challenge success!";
        if (info != "") {
            status.innerHTML = `Done! Took ${t1 - t0}ms, ${info}`;
        } else {
            status.innerHTML = `Done! Took ${t1 - t0}ms`;
        }

        setTimeout(() => {
            const redir = window.location.href;
            window.location.href = u("{{ .Path }}/verify-challenge", {
                __goaway_token: result,
                __goaway_challenge: "{{ .Challenge }}",
                __goaway_redirect: redir,
                __goaway_id: "{{ .Id }}",
                __goaway_elapsedTime: t1 - t0,
            });
        }, 500);
    } catch (err) {
        title.innerHTML = "Oh no!";
        status.innerHTML = `Failed to challenge: ${err.message}`;
        spinner.innerHTML = "";
        spinner.style.display = "none";
    }
})();