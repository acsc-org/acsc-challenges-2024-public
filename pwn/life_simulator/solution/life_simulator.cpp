

#include <iostream>
#include <vector>

#define pos_neg_zero(x) x > 0 ? 1 : (x < 0 ? -1 : 0)

enum MapSize { NoneMapSize, SmallMapSize, MediumMapSize, LargeMapSize };
enum NewSpawn { NoNewSpawn, YesNewSpawn };
enum Status { AliveStatus, DeadStatus};
enum Entity { NoneEntity, LifeformEntity, FruitEntity, PoisonEntity };


std::string get_generation(int32_t num) {
    if (num >= 11 && num <= 13) {
        return " the " + std::to_string(num) + "th";
    } 
    switch (num % 10) {
        case 1:
            return " the " + std::to_string(num) + "st";
        case 2:
            return " the " + std::to_string(num) + "nd";
        case 3:
            return " the " + std::to_string(num) + "rd";
        default:
            return " the " + std::to_string(num) + "th";
    }
}

class Lifeform {

    public:
        Lifeform() {
            this->x_pos = 0;
            this->y_pos = 0;
            this->x_speed = 0;
            this->y_speed = 0;
            this->level = 0;
            this->number_of_children = 0;
            this->name = "Default";
            this->status = AliveStatus;
        }

        Lifeform(int32_t x_pos, int32_t y_pos, int32_t x_speed, int32_t y_speed, std::string name) {
            this->x_pos = x_pos;
            this->y_pos = y_pos;
            this->x_speed = x_speed;
            this->y_speed = y_speed;
            this->level = 0;
            this->number_of_children = 0;
            this->name = name;
            this->status = AliveStatus;
        }

        int32_t get_x_pos() {
            return this->x_pos;
        }

        int32_t get_y_pos() {
            return this->y_pos;
        }

        int32_t get_x_speed() {
            return this->x_speed;
        }

        int32_t get_y_speed() {
            return this->y_speed;
        }

        void set_x_speed(int32_t x_speed) {
            this->x_speed = x_speed;
        }

        void set_y_speed(int32_t y_speed) {
            this->y_speed = y_speed;
        }

        std::string get_name() {
            return this->name;
        }

        void flip_x_speed() {
            this->x_speed = -(this->x_speed);
        }

        void flip_y_speed() {
            this->y_speed = -(this->y_speed);
        }

        void move() {
            this->x_pos += pos_neg_zero(this->x_speed); 
            this->y_pos += pos_neg_zero(this->y_speed); 
        }

        NewSpawn level_up() {
            if(++this->level >= 3) {
                this->level = 0;
                this->number_of_children++;
                return YesNewSpawn;
            }
            return NoNewSpawn;
        }

        void level_down() {
            if(--this->level < 0) {
                this->status = DeadStatus;
                return;
            }
            this->status = AliveStatus;
        }

        int32_t get_number_of_children() {
            return this->number_of_children;
        }

        void set_dead() {
            this->status = DeadStatus;
        }

        Status get_status() {
            return this->status;
        }

        void print_stats() { 
            std::cout << "Lifeform name: " << this->name << std::endl;
            std::cout << "Lifeform position: (" << this->x_pos << ", " << this->y_pos << ")" << std::endl;
            std::cout << "Lifeform speed: (" << this->x_speed << ", " << this->y_speed << ")" << std::endl;
            std::cout << "Lifeform level: " << this->level << std::endl;
            std::cout << "Lifeform children: " << this->number_of_children << std::endl;
            std::cout << std::endl;
        }

    private:
        int32_t x_pos;
        int32_t y_pos;
        int32_t x_speed;
        int32_t y_speed;
        int32_t level;
        int32_t number_of_children;
        Status status;
        std::string name;
};

class Map {
    public:
        Map() {
            this->x_size = 35;
            this->y_size = 23;
            area = new char[this->y_size * this->x_size];
            entity_area = new Entity[this->y_size * this->x_size];
            for(int32_t i = 0; i < this->y_size; i++) {
                for(int32_t j = 0; j < this->x_size; j++) {
                    entity_area[i*this->x_size + j] = NoneEntity;
                    area[i*this->x_size + j] = ' ';
                }
            }
        }

        Map(int32_t x_size, int32_t y_size) {
            this->x_size = x_size;
            this->y_size = y_size;
            area = new char[this->y_size * this->x_size];
            entity_area = new Entity[this->y_size * this->x_size];
            for(int32_t i = 0; i < this->y_size; i++) {
                for(int32_t j = 0; j < this->x_size; j++) {
                    entity_area[i*this->x_size + j] = NoneEntity;
                    area[i*this->x_size + j] = ' ';
                }
            }
        }

        ~Map() {
            delete[] this->area;
            delete[] this->entity_area;
        }
        
        int32_t get_x_size() {
            return this->x_size;
        }

        int32_t get_y_size() {
            return this->y_size;
        }

        void print_area() {
            for(int32_t i = 0; i < this->x_size + 2; i++) std::cout << "#"; std::cout << std::endl;
            for(int32_t i = 0; i < this->y_size; i++) {
                std::cout << "#";
                for(int32_t j = 0; j < this->x_size; j++) {
                    switch(entity_area[i*this->x_size + j]) {
                        case FruitEntity:
                            std::cout << "o";
                            break;
                        case PoisonEntity:
                            std::cout << "x";
                            break;
                        default:
                            std::cout << area[i*this->x_size + j];
                            break;
                    }
                }
                std::cout << "#" << std::endl;
            }
            for(int32_t i = 0; i < this->x_size + 2; i++) std::cout << "#"; std::cout << std::endl;
        }

        Entity get_area_entity(int32_t x_pos, int32_t y_pos) {
            return this->entity_area[y_pos*this->x_size + x_pos]; 
        }
        
        void set_area(int32_t x_pos, int32_t y_pos, char indicator, Entity entity) {
            switch(entity) {
                case LifeformEntity:
                    this->area[y_pos*this->x_size + x_pos] = indicator;
                    this->entity_area[y_pos*this->x_size + x_pos] = LifeformEntity;
                    break;
                case FruitEntity:
                    this->entity_area[y_pos*this->x_size + x_pos] = FruitEntity;
                    break;
                case PoisonEntity:
                    this->entity_area[y_pos*this->x_size + x_pos] = PoisonEntity;
                    break;
                default:
                    this->area[y_pos*this->x_size + x_pos] = ' ';
                    this->entity_area[y_pos*this->x_size + x_pos] = NoneEntity;
                    break;
            }
        }

        void print_stats() {
            std::cout << "Map size: " << this->x_size << " x " << this->y_size << std::endl;
        }

    private:
        int32_t x_size;
        int32_t y_size;
        char *area;
        Entity *entity_area;
};

class Simulation {

    public:
        Simulation() {
            this->simulation_map = new Map();
            this->number_of_steps = 0;
            this->lifeforms.reserve(20);
        }

        Simulation(int32_t x_size, int32_t y_size) {
            this->simulation_map = new Map(x_size, y_size);
            this->number_of_steps = 0;
            this->lifeforms.reserve(20);
        }

        void add_lifeform(int32_t x_pos, int32_t y_pos, int32_t x_speed, int32_t y_speed, std::string name) {
            if(x_pos >= 0 && 
                    y_pos >= 0 && 
                    x_pos < this->simulation_map->get_x_size() && 
                    y_pos < this->simulation_map->get_y_size() && 
                    this->simulation_map->get_area_entity(x_pos, y_pos) == NoneEntity) {
                Lifeform new_lifeform = Lifeform(x_pos, y_pos, x_speed, y_speed, name);
                this->lifeforms.push_back(new_lifeform);
                this->simulation_map->set_area(x_pos, y_pos, name[0], LifeformEntity);
            } else {
                std::cout << "Invalid position for entity" << std::endl;
            }
        }

        void add_fruit(int32_t x_pos, int32_t y_pos) {
            if(x_pos >= 0 && 
                    y_pos >= 0 && 
                    x_pos < this->simulation_map->get_x_size() && 
                    y_pos < this->simulation_map->get_y_size()) {
                this->simulation_map->set_area(x_pos, y_pos, ' ', FruitEntity);
            } else {
                std::cout << "Invalid position for entity" << std::endl;
            }
        }

        void add_poison(int32_t x_pos, int32_t y_pos) {
            if(x_pos >= 0 && 
                    y_pos >= 0 && 
                    x_pos < this->simulation_map->get_x_size() && 
                    y_pos < this->simulation_map->get_y_size()) {
                this->simulation_map->set_area(x_pos, y_pos, ' ', PoisonEntity);
            } else {
                std::cout << "Invalid position for entity" << std::endl;
            }
        }

        void check_lifeform(auto lifeform) {
            int32_t future_x_pos = lifeform->get_x_pos() + pos_neg_zero(lifeform->get_x_speed());
            int32_t future_y_pos = lifeform->get_y_pos() + pos_neg_zero(lifeform->get_y_speed());
            if(future_x_pos < 0 || future_x_pos >= this->simulation_map->get_x_size()) lifeform->flip_x_speed();   
            if(future_y_pos < 0 || future_y_pos >= this->simulation_map->get_y_size()) lifeform->flip_y_speed();   
        }

        void simulate() {
            this->number_of_steps++;
            for(auto it = this->lifeforms.begin(); it != this->lifeforms.end(); ++it) {
                int32_t prev_x_pos = it->get_x_pos();
                int32_t prev_y_pos = it->get_y_pos();
                this->check_lifeform(it);
                it->move();
                int32_t curr_x_pos = it->get_x_pos();
                int32_t curr_y_pos = it->get_y_pos();

                if(curr_x_pos <= 0 || curr_x_pos >= this->simulation_map->get_x_size() - 1) it->flip_x_speed();
                if(curr_y_pos <= 0 || curr_y_pos >= this->simulation_map->get_y_size() - 1) it->flip_y_speed();

                this->simulation_map->set_area(prev_x_pos, prev_y_pos, ' ', NoneEntity);
                Entity curr_pos_entity = this->simulation_map->get_area_entity(curr_x_pos, curr_y_pos);
                if(curr_pos_entity == FruitEntity) {
                    this->simulation_map->set_area(curr_x_pos, curr_y_pos, ' ', NoneEntity);
                    if(it->level_up() == YesNewSpawn) {
                        std::string new_spawn_name = it->get_name() + get_generation(it->get_number_of_children() + 1); 
                        this->add_lifeform(prev_x_pos, prev_y_pos, it->get_x_speed()*(-1), it->get_y_speed()*(-1), new_spawn_name); 
                    }
                } else if(curr_pos_entity == PoisonEntity) {
                    this->simulation_map->set_area(curr_x_pos, curr_y_pos, ' ', NoneEntity);
                    it->level_down();
                }
            }
            
            for(auto it = this->lifeforms.begin(); it != this->lifeforms.end(); it++) {
                int32_t curr_x_pos = it->get_x_pos();
                int32_t curr_y_pos = it->get_y_pos();
                for(auto it_2 = this->lifeforms.begin(); it_2 != this->lifeforms.end(); it_2++) {
                    if(curr_x_pos == it_2->get_x_pos() && curr_y_pos == it_2->get_y_pos() && it_2 != it) {
                        it_2->set_dead();
                    }
                }
            }

            for(auto it = this->lifeforms.rbegin(); it != this->lifeforms.rend(); it++) {
                if(it->get_status() == DeadStatus) {
                    *it = this->lifeforms.back();
                    this->lifeforms.pop_back();
                }
            }

            for(auto it : this->lifeforms) 
                this->simulation_map->set_area(it.get_x_pos(), it.get_y_pos(), it.get_name()[0], LifeformEntity);
        }

        void print_stats() {
            std::cout << "Simulation steps: " << this->number_of_steps << std::endl;
            this->simulation_map->print_stats();
            std::cout << "Number of lifeforms: " << this->lifeforms.size() << std::endl;
            std::cout << "Lifeform stats: " << std::endl << std::endl;

            for(auto it : this->lifeforms) {
                it.print_stats();
            }
        }

        void print_area() {
            this->simulation_map->print_area();
        }

    private:
        int32_t number_of_steps;
        Map *simulation_map;
        std::vector<Lifeform> lifeforms;
};

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
}

void print_banner() {
    std::cout << "##.......####.########.########.....######..####.##.....##.##.....##.##..........###....########..#######..########." << std::endl;
    std::cout << "##........##..##.......##..........##....##..##..###...###.##.....##.##.........##.##......##....##.....##.##.....##" << std::endl;
    std::cout << "##........##..##.......##..........##........##..####.####.##.....##.##........##...##.....##....##.....##.##.....##" << std::endl;
    std::cout << "##........##..######...######.......######...##..##.###.##.##.....##.##.......##.....##....##....##.....##.########." << std::endl;
    std::cout << "##........##..##.......##................##..##..##.....##.##.....##.##.......#########....##....##.....##.##...##.." << std::endl;
    std::cout << "##........##..##.......##..........##....##..##..##.....##.##.....##.##.......##.....##....##....##.....##.##....##." << std::endl;
    std::cout << "########.####.##.......########.....######..####.##.....##..#######..########.##.....##....##.....#######..##.....##" << std::endl;
}

MapSize choose_map_size() {
    std::string choice;
    std::cout << "Choose Map Size:" << std::endl;
    std::cout << "(S)mall (16x9)/ (M)edium (23x14) / (L)arge (41x25)" << std::endl;
    std::cout << "S/M/L: ";
    std::cin >> choice;

    if(choice == "S")
        return SmallMapSize;
    if(choice == "M")
        return MediumMapSize;
    if(choice == "L")
        return LargeMapSize;
    return  NoneMapSize;
}

void menu() {
    std::cout << "1. Simulate single step" << std::endl;
    std::cout << "2. Add Lifeform" << std::endl;
    std::cout << "3. Add fruit" << std::endl;
    std::cout << "4. Add poison" << std::endl;
    std::cout << "5. Show simulation stats" << std::endl;
    std::cout << "6. Exit" << std::endl;
    std::cout << "> ";
}

int main(int argc, char *argv[]) {
    init();
    print_banner();

    Simulation *sim;
    MapSize mapSize = choose_map_size();
    switch(mapSize) {
        case SmallMapSize:
            sim = new Simulation(16, 9);
            break;
        case MediumMapSize:
            sim = new Simulation(23, 14);
            break;
        case LargeMapSize:
            sim = new Simulation(41, 25);
            break;
        default:
            sim = new Simulation();
            break;
    }
    while(1) {
        uint32_t choice = 0;
        sim->print_area();
        menu();
        std::cin >> choice;
        if(!std::cin.good())    {
            exit(1);
        }
        switch(choice) {
            case 1:
                sim->simulate();
                break;
            case 2:
                {
                    int32_t x_pos, y_pos, x_speed, y_speed;
                    std::string name;
                    std::cout << "X position: ";
                    std::cin >> x_pos;
                    std::cout << "Y position: ";
                    std::cin >> y_pos;
                    std::cout << "X speed (min: -1, max: 1): ";
                    std::cin >> x_speed;
                    x_speed = pos_neg_zero(x_speed);
                    std::cout << "Y speed (min: -1, max: 1): ";
                    std::cin >> y_speed;
                    y_speed = pos_neg_zero(y_speed);
                    std::cout << "Name: ";
                    std::cin >> name;
                    sim->add_lifeform(x_pos, y_pos, x_speed, y_speed, name);
                    break;
                }
            case 3:
                {
                    int32_t x_pos, y_pos;
                    std::cout << "X position: ";
                    std::cin >> x_pos;
                    std::cout << "Y position: ";
                    std::cin >> y_pos;
                    sim->add_fruit(x_pos, y_pos);
                    break;
                }
            case 4:
                {
                    int32_t x_pos, y_pos;
                    std::cout << "X position: ";
                    std::cin >> x_pos;
                    std::cout << "Y position: ";
                    std::cin >> y_pos;
                    sim->add_poison(x_pos, y_pos);
                    break;
                }
            case 5:
                sim->print_stats();
                break;
            case 6:
                std::cout << "Bye bye!" << std::endl;
                exit(0);
            default:
                std::cout << "Invalid choice!" << std::endl;
                break;
        }
    }
}
