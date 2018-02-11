class GameObject
{
	
};

class GameObjectManager
{
	char Padding01[0x8];
	GameObject** Objects;
	int mObjects; // Maximum Amount of Objects
};