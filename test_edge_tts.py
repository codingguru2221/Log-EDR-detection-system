import asyncio
import edge_tts

async def test():
    voices = await edge_tts.list_voices()
    
    # Show all Indian language voices
    indian_locales = ['en-IN', 'hi-IN', 'mr-IN', 'gu-IN', 'te-IN', 'ta-IN', 
                      'kn-IN', 'ml-IN', 'bn-IN', 'pa-IN', 'or-IN', 'as-IN']
    
    for locale in indian_locales:
        matches = [v for v in voices if v['Locale'] == locale]
        if matches:
            print(f"✅ {locale}: {len(matches)} voice(s)")
            for v in matches:
                print(f"   {v['ShortName']} ({v['Gender']})")
        else:
            print(f"❌ {locale}: No voices")
    
    # Test actual TTS generation for Marathi
    print("\n=== Testing Marathi TTS ===")
    mr_voice = "mr-IN-AarohiNeural"
    communicate = edge_tts.Communicate("नमस्कार, मी त्रिनेत्र AI आहे.", mr_voice)
    audio_data = b""
    async for chunk in communicate.stream():
        if chunk["type"] == "audio":
            audio_data += chunk["data"]
    print(f"Marathi audio: {len(audio_data)} bytes")
    
    # Test Gujarati
    print("\n=== Testing Gujarati TTS ===")
    gu_voice = "gu-IN-DhwaniNeural"
    communicate = edge_tts.Communicate("નમસ્તે, હું ત્રિનેત્ર AI છું.", gu_voice)
    audio_data = b""
    async for chunk in communicate.stream():
        if chunk["type"] == "audio":
            audio_data += chunk["data"]
    print(f"Gujarati audio: {len(audio_data)} bytes")

asyncio.run(test())
