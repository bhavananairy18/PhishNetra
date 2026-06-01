document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const score = urlParams.get('score');

    let reasons = [];
    try {
        reasons = JSON.parse(decodeURIComponent(urlParams.get('reasons') || '[]'));
    } catch (e) {
        console.error('Could not parse reasons', e);
    }

    // Populate data
    if (score) {
        document.getElementById('risk-score').textContent = `${score}/100`;
    }

    // Play local audio warning once per session/tab warning appearance
    if (!sessionStorage.getItem('phishnetra_sound_played')) {
        chrome.storage.local.get({ soundAlerts: true }, (data) => {
            if (data.soundAlerts) {
                const playAudio = () => {
                    try {
                        const audio = new Audio(chrome.runtime.getURL('sound.mpeg'));
                        audio.play()
                            .then(() => {
                                sessionStorage.setItem('phishnetra_sound_played', 'true');
                                removeListeners();
                            })
                            .catch(e => {
                                console.log('Audio playback deferred (waiting for interaction on blocked page).');
                            });
                    } catch (err) {
                        console.error('Audio initialization error:', err);
                    }
                };

                const removeListeners = () => {
                    document.removeEventListener('click', playAudio);
                    document.removeEventListener('keydown', playAudio);
                };

                // Try immediate play
                try {
                    const audio = new Audio(chrome.runtime.getURL('sound.mpeg'));
                    audio.play()
                        .then(() => {
                            sessionStorage.setItem('phishnetra_sound_played', 'true');
                        })
                        .catch(e => {
                            console.log('Immediate audio blocked on blocked page, waiting for interaction.');
                            document.addEventListener('click', playAudio);
                            document.addEventListener('keydown', playAudio);
                        });
                } catch (err) {
                    console.error('Audio initialization error:', err);
                }
            }
        });
    }

    const reasonsList = document.getElementById('reasons-list');
    if (reasons && reasons.length > 0) {
        reasons.forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            reasonsList.appendChild(li);
        });
    } else {
        reasonsList.innerHTML = '<li>Analyzing page attributes...</li>';
    }

    // Button actions
    document.getElementById('btn-back').addEventListener('click', () => {
        // Go to history back if possible, else close tab
        if (window.history.length > 1) {
            window.history.back();
        } else {
            chrome.tabs.getCurrent(tab => {
                if (tab) {
                    chrome.tabs.remove(tab.id);
                } else {
                    window.close();
                }
            });
        }
    });
});

